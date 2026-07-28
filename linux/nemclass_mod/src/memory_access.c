// SPDX-License-Identifier: GPL-2.0
/*
 * nemclass_mod — kernel-side remote memory access, region enumeration and
 * ptrace status. Runs entirely in sleepable ioctl (process) context.
 *
 * Memory read/write goes through access_process_vm(), which holds the target
 * mm and copies via GUP — it does NOT re-check ptrace_may_access(), so this
 * path works where userspace process_vm_readv() is blocked by Yama.
 */
#define pr_fmt(fmt) "nemclass: " fmt

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "internal.h"

#define NEM_CHUNK	(64 * 1024)	/* bounce-buffer chunk size */

struct task_struct *nemclass_get_task(pid_t pid)
{
	struct pid *p = find_get_pid(pid);
	struct task_struct *task;

	if (!p)
		return NULL;
	task = get_pid_task(p, PIDTYPE_PID);
	put_pid(p);
	return task;
}

/* Common transfer engine for READ (write_to_target=false) and WRITE. */
static long nemclass_transfer(void __user *arg, bool write_to_target)
{
	struct nemclass_rw rw;
	struct task_struct *task;
	void *kbuf;
	unsigned int flags = FOLL_FORCE | (write_to_target ? FOLL_WRITE : 0);
	u64 done = 0;
	long ret = 0;

	if (copy_from_user(&rw, arg, sizeof(rw)))
		return -EFAULT;

	/*
	 * Reject a request whose target or user range would wrap u64: otherwise
	 * `rw.addr + done` / `rw.ubuf + done` below could silently roll over and
	 * target a different address. (access_process_vm / copy_*_user would fail
	 * the wrapped access anyway, but rejecting up front is clearer.)
	 */
	if (rw.len > U64_MAX - rw.addr || rw.len > U64_MAX - rw.ubuf)
		return -EINVAL;

	task = nemclass_get_task(rw.pid);
	if (!task)
		return -ESRCH;

	if (rw.len == 0)
		goto out_put;

	kbuf = kvmalloc(min_t(u64, rw.len, NEM_CHUNK), GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		goto out_put;
	}

	while (done < rw.len) {
		int this = min_t(u64, rw.len - done, NEM_CHUNK);
		void __user *uptr = (void __user *)(unsigned long)(rw.ubuf + done);
		int n;

		/*
		 * rw.len is an unbounded u64: a multi-GB transfer would otherwise
		 * spin in the kernel uninterruptibly. Bail on a pending signal and
		 * yield each chunk so this can't trip soft-lockup / RCU-stall.
		 */
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		cond_resched();

		if (write_to_target) {
			if (copy_from_user(kbuf, uptr, this)) {
				ret = -EFAULT;
				break;
			}
			n = access_process_vm(task, rw.addr + done, kbuf, this,
					      flags);
			if (n <= 0)
				break;
		} else {
			n = access_process_vm(task, rw.addr + done, kbuf, this,
					      flags);
			if (n <= 0)
				break;
			if (copy_to_user(uptr, kbuf, n)) {
				ret = -EFAULT;
				break;
			}
		}

		done += n;
		if (n < this)		/* hit an unmapped/short region */
			break;
	}

	kvfree(kbuf);

out_put:
	put_task_struct(task);
	if (ret)
		return ret;

	rw.done = done;
	if (copy_to_user(arg, &rw, sizeof(rw)))
		return -EFAULT;
	return 0;
}

long nemclass_do_read(void __user *arg)
{
	return nemclass_transfer(arg, false);
}

long nemclass_do_write(void __user *arg)
{
	return nemclass_transfer(arg, true);
}

long nemclass_do_enum_regions(void __user *arg)
{
	struct nemclass_enum_regions req;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	void __user *out;
	unsigned long addr = 0;
	u32 count = 0, total = 0;
	long ret = 0;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	task = nemclass_get_task(req.pid);
	if (!task)
		return -ESRCH;
	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -ESRCH;
	}
	out = (void __user *)(unsigned long)req.ubuf;

	down_read(&mm->mmap_lock);
	/*
	 * vm_next is gone on maple-tree kernels; walk forward by repeatedly
	 * asking for the first VMA ending after the previous VMA's end. Uses
	 * only the exported find_vma().
	 */
	while ((vma = find_vma(mm, addr)) != NULL) {
		struct nemclass_region reg = {};

		reg.start = vma->vm_start;
		reg.end   = vma->vm_end;
		reg.prot  = ((vma->vm_flags & VM_READ)  ? 1 : 0) |
			    ((vma->vm_flags & VM_WRITE) ? 2 : 0) |
			    ((vma->vm_flags & VM_EXEC)  ? 4 : 0);
		if (vma->vm_file)
			reg.file_off = (u64)vma->vm_pgoff << PAGE_SHIFT;

		if (count < req.max) {
			if (copy_to_user(out + (size_t)count * sizeof(reg),
					 &reg, sizeof(reg))) {
				ret = -EFAULT;
				break;
			}
			count++;
		}
		total++;

		if (vma->vm_end <= addr)	/* overflow guard */
			break;
		addr = vma->vm_end;
	}
	up_read(&mm->mmap_lock);

	mmput(mm);
	put_task_struct(task);
	if (ret)
		return ret;

	req.count = count;
	req.total = total;
	if (copy_to_user(arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

int nemclass_resolve_file_offset(struct task_struct *task, u64 addr,
				 struct inode **out_inode, loff_t *out_off)
{
	struct mm_struct *mm = get_task_mm(task);
	struct vm_area_struct *vma;
	int ret = 0;

	if (!mm)
		return -ESRCH;

	down_read(&mm->mmap_lock);
	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start || !vma->vm_file) {
		ret = -EINVAL;
		goto out;
	}
	*out_inode = igrab(file_inode(vma->vm_file));
	if (!*out_inode) {
		ret = -ENOENT;
		goto out;
	}
	*out_off = (loff_t)(addr - vma->vm_start) +
		   ((loff_t)vma->vm_pgoff << PAGE_SHIFT);
out:
	up_read(&mm->mmap_lock);
	mmput(mm);
	return ret;
}

long nemclass_do_ptrace_query(void __user *arg)
{
	struct nemclass_ptrace req;
	struct task_struct *task, *tracer;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	task = nemclass_get_task(req.pid);
	if (!task)
		return -ESRCH;

	rcu_read_lock();
	req.traced = READ_ONCE(task->ptrace) ? 1 : 0;
	tracer = ptrace_parent(task);
	req.tracer_pid = tracer ? task_pid_vnr(tracer) : 0;
	rcu_read_unlock();

	put_task_struct(task);
	if (copy_to_user(arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

long nemclass_do_ptrace_hide(void __user *arg)
{
	struct nemclass_ptrace req;
	struct task_struct *task, *tracer;
	unsigned int old;

	if (!nemclass_allow_ptrace_hide) {
		pr_warn("PTRACE_HIDE refused; load with allow_ptrace_hide=1 to enable (experimental)\n");
		return -EPERM;
	}
	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	task = nemclass_get_task(req.pid);
	if (!task)
		return -ESRCH;

	old = READ_ONCE(task->ptrace);
	if (!old) {
		/* Not traced: nothing to hide, and nothing unsafe to touch. */
		put_task_struct(task);
		return 0;
	}
	/*
	 * Refuse when a tracer in a *different* thread group is attached: clearing
	 * the flag word out from under a live external tracer races the ptrace
	 * state machine (we hold neither tasklist_lock nor the tracee siglock,
	 * neither exported to modules) and can corrupt it. Only let through the
	 * same-process self-ptrace anti-debug case this is actually meant for.
	 */
	rcu_read_lock();
	tracer = ptrace_parent(task);
	if (tracer && !same_thread_group(tracer, task)) {
		rcu_read_unlock();
		pr_warn_ratelimited("PTRACE_HIDE pid=%d refused: external tracer attached (would race it)\n",
				    req.pid);
		put_task_struct(task);
		return -EBUSY;
	}
	rcu_read_unlock();
	/*
	 * EXPERIMENTAL, HIGH RISK. Best-effort spoof: clear the ptrace flag word
	 * so /proc/<pid>/status TracerPid renders 0, defeating self-check
	 * anti-debug. A correct detach needs tasklist_lock / __ptrace_unlink,
	 * neither exported to modules, so we can neither unlink the tracer nor
	 * even take the lock that serialises attach/detach. Against a LIVE
	 * external tracer this races and leaves inconsistent tracee state — only
	 * use on a target that self-ptraces as anti-debug. Gated off by default
	 * (allow_ptrace_hide).
	 */
	WRITE_ONCE(task->ptrace, 0);
	pr_warn_ratelimited("PTRACE_HIDE pid=%d cleared ptrace (was 0x%x) — EXPERIMENTAL, may destabilise a live tracer\n",
			    req.pid, old);

	put_task_struct(task);
	return 0;
}
