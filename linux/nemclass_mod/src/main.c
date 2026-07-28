// SPDX-License-Identifier: GPL-2.0
/*
 * nemclass_mod — /proc interface, symmetric-key auth, and ioctl dispatch.
 *
 * The interface lives at /proc/nemclass/attach. Opening it is gated by the
 * uid/gid allowlist in access.c (fixing "permission denied" without a
 * root-only device node); every gated ioctl is then further gated behind a
 * shared-secret handshake (NEMCLASS_IOC_AUTH). The key is provided at module
 * load (key=<hex>) and matched constant-time; without it the module fails
 * closed. A companion read-only /proc/nemclass/acl reports the live policy.
 * Memory access and the debugger engine live in the sibling translation units
 * (memory_access.c, debugger.c); the access policy lives in access.c.
 */
#define pr_fmt(fmt) "nemclass: " fmt

#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/hex.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <crypto/algapi.h>	/* crypto_memneq */

#include "internal.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Thomas Wright");
MODULE_DESCRIPTION("nemclass_mod: non-ptrace debugger + kernel-side memory access");
MODULE_VERSION("2.0");

static char *key;
module_param(key, charp, 0400);
MODULE_PARM_DESC(key,
	"Shared symmetric key as raw hex (no 0x); clients must present it via NEMCLASS_IOC_AUTH");

bool nemclass_allow_ptrace_hide;
module_param_named(allow_ptrace_hide, nemclass_allow_ptrace_hide, bool, 0644);
MODULE_PARM_DESC(allow_ptrace_hide,
	"Enable the experimental PTRACE_HIDE ioctl (default off)");

/* Parsed key. key_len == 0 means "no key configured" => fail closed. */
static u8  nemclass_key[NEMCLASS_KEY_MAX];
static u32 nemclass_key_len;

/* Latch a fd's AUTH shut after this many wrong guesses (brute-force backstop). */
#define NEMCLASS_AUTH_MAX_FAILURES	16u

static long nemclass_do_auth(struct nemclass_session *sess, void __user *arg)
{
	struct nemclass_auth a;
	long ret = 0;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;

	if (nemclass_key_len == 0) {
		pr_warn_ratelimited("AUTH refused: module loaded without key=\n");
		ret = -EACCES;
		goto out;
	}
	/*
	 * Once a fd has burned through its guess budget it stays locked: the
	 * client must reopen (which is itself gated by the uid/gid allowlist).
	 */
	if (sess->auth_failures >= NEMCLASS_AUTH_MAX_FAILURES) {
		pr_warn_ratelimited("AUTH locked on this fd after %u failures; reopen to retry\n",
				    sess->auth_failures);
		ret = -EACCES;
		goto out;
	}
	if (a.key_len != nemclass_key_len ||
	    crypto_memneq(a.key, nemclass_key, nemclass_key_len)) {
		sess->auth_failures++;
		/*
		 * Escalating throttle. The compare is already constant-time; this
		 * blunts online brute force by making each wrong guess cost real
		 * wall-clock. Because the caller sleeps here, it also slows the
		 * open-many-fds variant, not just repeats on one fd.
		 */
		msleep(min_t(unsigned int, sess->auth_failures * 100u, 2000u));
		ret = -EACCES;
		goto out;
	}
	sess->authed = true;
	sess->auth_failures = 0;
out:
	memzero_explicit(&a, sizeof(a));
	return ret;
}

static long nemclass_ioctl(struct file *file, unsigned int cmd,
			   unsigned long uarg)
{
	struct nemclass_session *sess = file->private_data;
	void __user *arg = (void __user *)uarg;

	/* Unauthenticated operations. */
	switch (cmd) {
	case NEMCLASS_IOC_VERSION: {
		struct nemclass_version v = { .abi = NEMCLASS_ABI_VERSION };

		if (copy_to_user(arg, &v, sizeof(v)))
			return -EFAULT;
		return 0;
	}
	case NEMCLASS_IOC_AUTH:
		return nemclass_do_auth(sess, arg);
	}

	/* Everything else requires a successful handshake on this fd. */
	if (!sess->authed)
		return -EACCES;

	/*
	 * Re-assert the open-time allowlist against the *current* caller on every
	 * privileged ioctl. Access is checked once in ->open, but an authenticated
	 * fd can be handed to another process (SCM_RIGHTS) or inherited across
	 * fork/exec by a lower-privileged child; re-checking here denies a holder
	 * that is not itself allowlisted (CAP_SYS_ADMIN still always passes), and
	 * also picks up a live allowlist edit that has since removed the caller.
	 */
	if (nemclass_access_check_open())
		return -EACCES;

	switch (cmd) {
	case NEMCLASS_IOC_READ:		return nemclass_do_read(arg);
	case NEMCLASS_IOC_WRITE:	return nemclass_do_write(arg);
	case NEMCLASS_IOC_ENUM_REGIONS:	return nemclass_do_enum_regions(arg);
	case NEMCLASS_IOC_BP_SET:	return nemclass_bp_set(sess, arg);
	case NEMCLASS_IOC_BP_CLEAR:	return nemclass_bp_clear(sess, arg);
	case NEMCLASS_IOC_WAIT_EVENT:	return nemclass_wait_event(sess, arg);
	case NEMCLASS_IOC_PTRACE_QUERY:	return nemclass_do_ptrace_query(arg);
	case NEMCLASS_IOC_PTRACE_HIDE:	return nemclass_do_ptrace_hide(arg);
	default:			return -ENOTTY;
	}
}

static int nemclass_open(struct inode *inode, struct file *file)
{
	struct nemclass_session *sess;
	int ret;

	/* uid/gid allowlist gate (access.c); refuses before any allocation. */
	ret = nemclass_access_check_open();
	if (ret)
		return ret;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		return -ENOMEM;

	mutex_init(&sess->lock);
	INIT_LIST_HEAD(&sess->slots);
	spin_lock_init(&sess->ev_lock);
	init_waitqueue_head(&sess->ev_wait);

	ret = kfifo_alloc(&sess->events, NEMCLASS_EVENT_DEPTH, GFP_KERNEL);
	if (ret) {
		mutex_destroy(&sess->lock);
		kfree(sess);
		return ret;
	}

	file->private_data = sess;
	return 0;
}

static int nemclass_release(struct inode *inode, struct file *file)
{
	struct nemclass_session *sess = file->private_data;

	nemclass_session_free_slots(sess);
	kfifo_free(&sess->events);
	mutex_destroy(&sess->lock);
	kfree(sess);
	return 0;
}

/*
 * The ioctl endpoint. Mode 0666 is intentional: the VFS permission bits are NOT
 * the access control — nemclass_open() enforces the uid/gid allowlist (and root
 * fails closed when no policy is loaded), so opening the node is always subject
 * to access.c regardless of the mode bits.
 */
static const struct proc_ops nemclass_attach_pops = {
	.proc_open		= nemclass_open,
	.proc_release		= nemclass_release,
	.proc_ioctl		= nemclass_ioctl,
	.proc_compat_ioctl	= compat_ptr_ioctl,
	.proc_lseek		= noop_llseek,
};

static int nemclass_acl_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, nemclass_access_proc_show, NULL);
}

static const struct proc_ops nemclass_acl_pops = {
	.proc_open	= nemclass_acl_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static struct proc_dir_entry *nemclass_proc_dir;

static int __init nemclass_parse_key(void)
{
	size_t slen;

	if (!key || !*key) {
		pr_warn("no key= given; all gated ioctls will be refused (fail closed)\n");
		return 0;
	}

	slen = strlen(key);
	if (slen % 2 || (slen / 2) > NEMCLASS_KEY_MAX) {
		pr_err("invalid key: need even-length hex, <= %u bytes\n",
		       NEMCLASS_KEY_MAX);
		memzero_explicit(key, slen);
		return -EINVAL;
	}
	if (hex2bin(nemclass_key, key, slen / 2)) {
		pr_err("invalid key: not valid hex\n");
		memzero_explicit(key, slen);
		return -EINVAL;
	}
	nemclass_key_len = slen / 2;
	/*
	 * Scrub the raw hex string now that we hold the parsed bytes: the charp
	 * param otherwise keeps the secret in kernel memory for the module's
	 * lifetime (and readable via /sys/module/.../parameters/key, mode 0400).
	 */
	memzero_explicit(key, slen);
	pr_info("auth key configured (%u bytes)\n", nemclass_key_len);
	return 0;
}

static int __init nemclass_init(void)
{
	struct proc_dir_entry *attach, *acl;
	int ret;

	ret = nemclass_parse_key();
	if (ret)
		return ret;

	/* Load the access policy before the interface becomes reachable. */
	nemclass_access_init();

	nemclass_proc_dir = proc_mkdir("nemclass", NULL);
	if (!nemclass_proc_dir) {
		pr_err("proc_mkdir(/proc/nemclass) failed\n");
		ret = -ENOMEM;
		goto err_access;
	}

	attach = proc_create("attach", 0666, nemclass_proc_dir,
			     &nemclass_attach_pops);
	if (!attach) {
		pr_err("proc_create(/proc/nemclass/attach) failed\n");
		ret = -ENOMEM;
		goto err_dir;
	}

	acl = proc_create("acl", 0444, nemclass_proc_dir, &nemclass_acl_pops);
	if (!acl) {
		pr_err("proc_create(/proc/nemclass/acl) failed\n");
		ret = -ENOMEM;
		goto err_dir;
	}

	pr_info("loaded: /proc/nemclass/attach (abi %u)\n", NEMCLASS_ABI_VERSION);
	return 0;

err_dir:
	proc_remove(nemclass_proc_dir);	/* removes the dir and any children */
	nemclass_proc_dir = NULL;
err_access:
	nemclass_access_exit();
	memzero_explicit(nemclass_key, sizeof(nemclass_key));
	return ret;
}

static void __exit nemclass_exit(void)
{
	proc_remove(nemclass_proc_dir);
	nemclass_access_exit();
	memzero_explicit(nemclass_key, sizeof(nemclass_key));
	pr_info("unloaded\n");
}

module_init(nemclass_init);
module_exit(nemclass_exit);
