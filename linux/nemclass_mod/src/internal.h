/* SPDX-License-Identifier: GPL-2.0 */
/*
 * nemclass_mod internal declarations shared across the module's translation
 * units (main.c, memory_access.c, debugger.c). Not part of the UAPI.
 */
#ifndef NEMCLASS_INTERNAL_H
#define NEMCLASS_INTERNAL_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/uprobes.h>
#include <linux/perf_event.h>

#include "nemclass.h"		/* UAPI (include/uapi via ccflags -I) */

#define NEMCLASS_EVENT_DEPTH	256	/* per-fd event ring, power of two */

/* Module param (main.c): gate the experimental PTRACE_HIDE path. */
extern bool nemclass_allow_ptrace_hide;

/*
 * Per-open-file session. One is allocated in ->open and freed in ->release.
 * `authed` is flipped only by a successful NEMCLASS_IOC_AUTH handshake; every
 * other ioctl refuses to run until then.
 */
struct nemclass_session {
	bool			authed;
	unsigned int		auth_failures;	/* per-fd failed AUTH count (throttle) */
	struct mutex		lock;		/* guards `slots` + `next_slot` */
	struct list_head	slots;		/* struct nemclass_slot.node */
	int			next_slot;

	/* Debug-event delivery for breakpoints/uprobes owned by this fd. */
	DECLARE_KFIFO_PTR(events, struct nemclass_event);
	spinlock_t		ev_lock;	/* serialises fifo producers */
	wait_queue_head_t	ev_wait;
};

/*
 * One registered breakpoint. Lives on session->slots and carries a back
 * pointer so the (non-sleeping) handler can enqueue into the owning fifo.
 */
struct nemclass_slot {
	struct list_head	node;
	struct nemclass_session	*sess;
	int			id;
	u32			kind;		/* NEMCLASS_BP_KIND_* */
	s32			pid;
	u64			addr;

	/* HW breakpoint */
	struct perf_event	*hw_bp;

	/* uprobe */
	struct inode		*inode;		/* igrab'd; iput on teardown */
	loff_t			offset;
	struct uprobe		*uprobe;
	struct uprobe_consumer	uc;
	struct mm_struct	*target_mm;	/* mmgrab'd; filter scopes hits to it */
};

/* --- memory_access.c -------------------------------------------------- */

/* Resolve a vpid to a refcounted task_struct (caller: put_task_struct). */
struct task_struct *nemclass_get_task(pid_t pid);

long nemclass_do_read(void __user *arg);
long nemclass_do_write(void __user *arg);
long nemclass_do_enum_regions(void __user *arg);
long nemclass_do_ptrace_query(void __user *arg);
long nemclass_do_ptrace_hide(void __user *arg);

/*
 * Resolve the file inode + file offset backing `addr` in `task`'s address
 * space (for uprobe registration). Returns an igrab'd inode (caller iput) via
 * *out_inode, or an ERR_PTR-style negative on failure.
 */
int nemclass_resolve_file_offset(struct task_struct *task, u64 addr,
				 struct inode **out_inode, loff_t *out_off);

/* --- access.c (open-time uid/gid ACL, live-reloaded numeric config) --- */

struct seq_file;

/* Start the config watcher and load the initial policy (called from init). */
void nemclass_access_init(void);
/* Stop the watcher and free the published allowlist (called from exit). */
void nemclass_access_exit(void);
/* Open-time gate: 0 if `current` may open the interface, -EACCES otherwise. */
int nemclass_access_check_open(void);
/* seq_file show() backing /proc/nemclass/acl. */
int nemclass_access_proc_show(struct seq_file *m, void *v);

/* --- debugger.c ------------------------------------------------------- */

long nemclass_bp_set(struct nemclass_session *sess, void __user *arg);
long nemclass_bp_clear(struct nemclass_session *sess, void __user *arg);
long nemclass_wait_event(struct nemclass_session *sess, void __user *arg);

/* Tear down every breakpoint owned by `sess` (called from ->release). */
void nemclass_session_free_slots(struct nemclass_session *sess);

#endif /* NEMCLASS_INTERNAL_H */
