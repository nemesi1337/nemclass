// SPDX-License-Identifier: GPL-2.0
/*
 * nemclass_mod — non-ptrace debugger engine.
 *
 * Two breakpoint kinds, neither using ptrace:
 *   HW     — register_user_hw_breakpoint() targets a specific task and is
 *            DR-backed; the overflow handler receives the target's pt_regs.
 *   UPROBE — the post-6.12 uprobe API (uprobe_register returns a struct
 *            uprobe *; teardown is the two-phase nosync + sync).
 *
 * Neither halts the target thread: a hit is captured as a register snapshot
 * and enqueued into the owning fd's event ring ("what accessed/executed here").
 * Handlers run in restricted (trap/IRQ) context — they only push into a
 * spinlock-guarded kfifo and wake the waiter; no sleeping, no copy_to_user.
 */
#define pr_fmt(fmt) "nemclass: " fmt

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hw_breakpoint.h>
#include <linux/jiffies.h>
#include <linux/kfifo.h>
#include <linux/list.h>
#include <linux/perf_event.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uprobes.h>
#include <linux/wait.h>

#include "internal.h"

static void nemclass_fill_regs(struct nemclass_event *ev, struct pt_regs *regs)
{
#ifdef CONFIG_X86_64
	ev->ip = regs->ip;
	ev->sp = regs->sp;
	ev->flags = regs->flags;
	ev->ax = regs->ax; ev->bx = regs->bx;
	ev->cx = regs->cx; ev->dx = regs->dx;
	ev->si = regs->si; ev->di = regs->di; ev->bp = regs->bp;
	ev->r8  = regs->r8;  ev->r9  = regs->r9;
	ev->r10 = regs->r10; ev->r11 = regs->r11;
	ev->r12 = regs->r12; ev->r13 = regs->r13;
	ev->r14 = regs->r14; ev->r15 = regs->r15;
#else
	ev->ip = instruction_pointer(regs);
	ev->sp = user_stack_pointer(regs);
#endif
}

/* Enqueue a hit into the owning fd's ring. Callable from trap/IRQ context. */
static void nemclass_emit_event(struct nemclass_slot *slot,
				struct pt_regs *regs)
{
	struct nemclass_session *sess = slot->sess;
	struct nemclass_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.slot = slot->id;
	ev.pid  = slot->pid;
	ev.tid  = task_pid_nr(current);
	ev.kind = slot->kind;
	ev.addr = slot->addr;
	nemclass_fill_regs(&ev, regs);

	/* Drop silently if the ring is full — producer must not block. */
	kfifo_in_spinlocked(&sess->events, &ev, 1, &sess->ev_lock);
	wake_up_interruptible(&sess->ev_wait);
}

#ifdef CONFIG_HAVE_HW_BREAKPOINT
static void nemclass_hw_handler(struct perf_event *bp,
				struct perf_sample_data *data,
				struct pt_regs *regs)
{
	struct nemclass_slot *slot = bp->overflow_handler_context;

	if (slot)
		nemclass_emit_event(slot, regs);
}

static int nemclass_hw_type(u32 type, int *out)
{
	switch (type) {
	case NEMCLASS_BP_X:  *out = HW_BREAKPOINT_X;  return 0;
	case NEMCLASS_BP_W:  *out = HW_BREAKPOINT_W;  return 0;
	case NEMCLASS_BP_R:  *out = HW_BREAKPOINT_R;  return 0;
	case NEMCLASS_BP_RW: *out = HW_BREAKPOINT_RW; return 0;
	default:             return -EINVAL;
	}
}

static int nemclass_hw_len(u32 len, int *out)
{
	switch (len) {
	case 1: *out = HW_BREAKPOINT_LEN_1; return 0;
	case 2: *out = HW_BREAKPOINT_LEN_2; return 0;
	case 4: *out = HW_BREAKPOINT_LEN_4; return 0;
	case 8: *out = HW_BREAKPOINT_LEN_8; return 0;
	default: return -EINVAL;
	}
}

static long nemclass_arm_hw(struct nemclass_slot *slot,
			    struct nemclass_bp_set *req,
			    struct task_struct *task)
{
	struct perf_event_attr attr;
	int bp_type, bp_len, ret;

	ret = nemclass_hw_type(req->type, &bp_type);
	if (ret)
		return ret;
	ret = nemclass_hw_len(req->len, &bp_len);
	if (ret)
		return ret;

	hw_breakpoint_init(&attr);
	attr.bp_addr = req->addr;
	attr.bp_type = bp_type;
	attr.bp_len  = bp_len;

	slot->hw_bp = register_user_hw_breakpoint(&attr, nemclass_hw_handler,
						  slot, task);
	if (IS_ERR(slot->hw_bp)) {
		ret = PTR_ERR(slot->hw_bp);
		slot->hw_bp = NULL;
		return ret;
	}
	return 0;
}
#else
static long nemclass_arm_hw(struct nemclass_slot *slot,
			    struct nemclass_bp_set *req,
			    struct task_struct *task)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_HAVE_HW_BREAKPOINT */

#ifdef CONFIG_UPROBES
static int nemclass_uprobe_handler(struct uprobe_consumer *self,
				   struct pt_regs *regs, __u64 *data)
{
	struct nemclass_slot *slot = container_of(self, struct nemclass_slot, uc);

	nemclass_emit_event(slot, regs);
	return 0;
}

static long nemclass_arm_uprobe(struct nemclass_slot *slot,
				struct nemclass_bp_set *req,
				struct task_struct *task)
{
	struct inode *inode = NULL;
	loff_t off = 0;
	long ret;

	ret = nemclass_resolve_file_offset(task, req->addr, &inode, &off);
	if (ret)
		return ret;

	slot->inode = inode;
	slot->offset = off;
	slot->uc.handler = nemclass_uprobe_handler;

	slot->uprobe = uprobe_register(inode, off, 0, &slot->uc);
	if (IS_ERR(slot->uprobe)) {
		ret = PTR_ERR(slot->uprobe);
		slot->uprobe = NULL;
		iput(inode);
		slot->inode = NULL;
		return ret;
	}
	return 0;
}
#else
static long nemclass_arm_uprobe(struct nemclass_slot *slot,
				struct nemclass_bp_set *req,
				struct task_struct *task)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_UPROBES */

/*
 * Detach a slot's kernel resources. HW breakpoints are torn down
 * synchronously (unregister_hw_breakpoint waits for the handler). Uprobes
 * use the two-phase API: this issues only the *nosync* half; the caller must
 * run uprobe_unregister_sync() once (batched) before reclaiming any slot that
 * held a uprobe, because in-flight handlers still dereference slot->uc.
 * Returns true if a uprobe nosync was issued.
 */
static bool nemclass_slot_detach(struct nemclass_slot *slot)
{
	bool need_sync = false;

#ifdef CONFIG_HAVE_HW_BREAKPOINT
	if (slot->hw_bp) {
		unregister_hw_breakpoint(slot->hw_bp);
		slot->hw_bp = NULL;
	}
#endif
#ifdef CONFIG_UPROBES
	if (slot->uprobe) {
		uprobe_unregister_nosync(slot->uprobe, &slot->uc);
		slot->uprobe = NULL;
		need_sync = true;
	}
#endif
	return need_sync;
}

/* Free a slot AFTER any required uprobe_unregister_sync() has completed. */
static void nemclass_slot_reclaim(struct nemclass_slot *slot)
{
	if (slot->inode) {
		iput(slot->inode);
		slot->inode = NULL;
	}
	kfree(slot);
}

long nemclass_bp_set(struct nemclass_session *sess, void __user *arg)
{
	struct nemclass_bp_set req;
	struct nemclass_slot *slot;
	struct task_struct *task;
	long ret;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	task = nemclass_get_task(req.pid);
	if (!task)
		return -ESRCH;

	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot) {
		put_task_struct(task);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&slot->node);
	slot->sess = sess;
	slot->kind = req.kind;
	slot->pid  = req.pid;
	slot->addr = req.addr;

	/*
	 * Assign the slot id BEFORE arming, so a handler that fires the instant
	 * the breakpoint is registered records the correct id. Defer the list
	 * insertion until arming succeeds: keeping the slot off the list until
	 * then stops a concurrent BP_CLEAR (another thread on this fd) from
	 * finding and freeing it mid-arm.
	 */
	mutex_lock(&sess->lock);
	slot->id = sess->next_slot++;
	mutex_unlock(&sess->lock);

	switch (req.kind) {
	case NEMCLASS_BP_KIND_HW:
		ret = nemclass_arm_hw(slot, &req, task);
		break;
	case NEMCLASS_BP_KIND_UPROBE:
		ret = nemclass_arm_uprobe(slot, &req, task);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	if (ret) {
		kfree(slot);
		put_task_struct(task);
		return ret;
	}

	mutex_lock(&sess->lock);
	list_add_tail(&slot->node, &sess->slots);
	mutex_unlock(&sess->lock);

	put_task_struct(task);

	req.slot = slot->id;
	if (copy_to_user(arg, &req, sizeof(req)))
		return -EFAULT;	/* slot stays registered; ->release reclaims */
	return 0;
}

long nemclass_bp_clear(struct nemclass_session *sess, void __user *arg)
{
	struct nemclass_bp_clear req;
	struct nemclass_slot *slot, *tmp, *found = NULL;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	mutex_lock(&sess->lock);
	list_for_each_entry_safe(slot, tmp, &sess->slots, node) {
		if (slot->id == req.slot) {
			list_del(&slot->node);
			found = slot;
			break;
		}
	}
	mutex_unlock(&sess->lock);

	if (!found)
		return -ENOENT;

	if (nemclass_slot_detach(found))
		uprobe_unregister_sync();
	nemclass_slot_reclaim(found);
	return 0;
}

void nemclass_session_free_slots(struct nemclass_session *sess)
{
	struct nemclass_slot *slot, *tmp;
	bool need_sync = false;
	LIST_HEAD(dead);

	mutex_lock(&sess->lock);
	list_splice_init(&sess->slots, &dead);
	mutex_unlock(&sess->lock);

	list_for_each_entry(slot, &dead, node)
		need_sync |= nemclass_slot_detach(slot);

	if (need_sync)
		uprobe_unregister_sync();

	list_for_each_entry_safe(slot, tmp, &dead, node) {
		list_del(&slot->node);
		nemclass_slot_reclaim(slot);
	}
}

long nemclass_wait_event(struct nemclass_session *sess, void __user *arg)
{
	struct nemclass_wait req;
	struct nemclass_event ev;
	long ret;	/* wait_event_interruptible_timeout returns long (jiffies) */

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	/*
	 * Contract: may return -EAGAIN even after a wake if another waiter on
	 * this fd drained the event first. Userspace must treat -EAGAIN (and
	 * -ETIMEDOUT) as "retry", not as a lost event.
	 */
	if (kfifo_is_empty(&sess->events)) {
		if (req.timeout_ms == 0)
			return -EAGAIN;

		if (req.timeout_ms < 0) {
			ret = wait_event_interruptible(sess->ev_wait,
					!kfifo_is_empty(&sess->events));
			if (ret)
				return -ERESTARTSYS;
		} else {
			ret = wait_event_interruptible_timeout(sess->ev_wait,
					!kfifo_is_empty(&sess->events),
					msecs_to_jiffies(req.timeout_ms));
			if (ret == 0)
				return -ETIMEDOUT;
			if (ret < 0)
				return -ERESTARTSYS;
		}
	}

	if (!kfifo_out_spinlocked(&sess->events, &ev, 1, &sess->ev_lock))
		return -EAGAIN;		/* drained by a concurrent waiter */

	if (copy_to_user((void __user *)(unsigned long)req.ubuf, &ev, sizeof(ev)))
		return -EFAULT;
	return 0;
}
