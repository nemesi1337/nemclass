// SPDX-License-Identifier: GPL-2.0
/*
 * nemclass_mod — open-time uid/gid access control, driven by a live-reloaded
 * numeric config file.
 *
 * This is the gate that decides whether a task may open the /proc interface at
 * all (it runs before the per-fd shared-key handshake in main.c, which still
 * guards the individual read/write ioctls). Because the kernel cannot resolve
 * user/group *names* — that is an NSS/userspace concept — the config lists
 * numeric IDs only:
 *
 *     # /etc/nemclass/access.conf
 *     uid 1000
 *     gid 1001
 *
 * A delayed workqueue re-stat()s the file every `access_poll_ms` and rebuilds
 * the allowlist whenever its mtime/size/inode changes, so edits take effect
 * without reloading the module. A missing, empty, or unparsable config fails
 * closed: only tasks holding CAP_SYS_ADMIN may open the interface, so the admin
 * can never lock themselves out.
 */
#define pr_fmt(fmt) "nemclass: " fmt

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/mm.h>			/* kvmalloc/kvfree */
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/workqueue.h>

#include "internal.h"

#define NEMCLASS_ACL_FILE_MAX	(16 * 1024)	/* cap on config file bytes */
#define NEMCLASS_ACL_MAX_ENTRY	256		/* per-kind entry cap */

static char *access_config = "/etc/nemclass/access.conf";
module_param(access_config, charp, 0444);
MODULE_PARM_DESC(access_config,
	"Path to the numeric uid/gid allowlist watched for live reload");

static unsigned int access_poll_ms = 2000;
module_param(access_poll_ms, uint, 0644);
MODULE_PARM_DESC(access_poll_ms,
	"Config re-stat interval in ms (0 disables polling after the initial load)");

/*
 * Immutable allowlist snapshot, published via RCU: nemclass_access_check_open()
 * readers take rcu_read_lock() and never block; the poll worker builds a fresh
 * snapshot and swaps it in, freeing the old one after a grace period. A NULL
 * pointer means "no policy loaded" => deny everyone but CAP_SYS_ADMIN.
 */
struct nemclass_acl {
	struct rcu_head	rcu;
	unsigned int	n_uid;
	unsigned int	n_gid;
	kuid_t		*uids;		/* n_uid entries */
	kgid_t		*gids;		/* n_gid entries */
};

static struct nemclass_acl __rcu *nemclass_acl;
static DEFINE_MUTEX(nemclass_acl_reload_lock);	/* serialises reloads/publish */
static struct delayed_work nemclass_acl_work;

/* Change-detection fingerprint of the last successfully stat'd config. */
static struct {
	bool		valid;
	u64		size;
	s64		mtime_sec;
	long		mtime_nsec;
	unsigned long	ino;
} nemclass_acl_fp;

/* Human-readable status for /proc/nemclass/acl; guarded by reload_lock. */
static char nemclass_acl_status[160] = "not yet loaded";

static void nemclass_acl_free(struct nemclass_acl *a)
{
	if (!a)
		return;
	kfree(a->uids);
	kfree(a->gids);
	kfree(a);
}

static void nemclass_acl_free_rcu(struct rcu_head *head)
{
	nemclass_acl_free(container_of(head, struct nemclass_acl, rcu));
}

/* Swap in `new` (may be NULL) and retire the previous snapshot. */
static void nemclass_acl_publish(struct nemclass_acl *new)
{
	struct nemclass_acl *old;

	old = rcu_replace_pointer(nemclass_acl, new,
				  lockdep_is_held(&nemclass_acl_reload_lock));
	if (old)
		call_rcu(&old->rcu, nemclass_acl_free_rcu);
}

/* Parse one already NUL-terminated line into `a`. Malformed lines are skipped. */
static void nemclass_acl_parse_line(struct nemclass_acl *a, char *line)
{
	char *kw, *val, *hash;
	unsigned long num;

	hash = strchr(line, '#');	/* strip inline comment */
	if (hash)
		*hash = '\0';

	line = strim(line);
	if (*line == '\0')		/* blank or comment-only */
		return;

	kw = line;
	val = strpbrk(line, " \t");
	if (!val)
		goto bad;
	*val++ = '\0';
	val = skip_spaces(val);

	if (kstrtoul(val, 0, &num))
		goto bad;

	if (!strcmp(kw, "uid")) {
		kuid_t k = make_kuid(&init_user_ns, num);

		if (!uid_valid(k))
			goto bad;
		if (a->n_uid < NEMCLASS_ACL_MAX_ENTRY)
			a->uids[a->n_uid++] = k;
		else
			pr_warn_ratelimited("acl: uid cap reached, dropping %lu\n", num);
	} else if (!strcmp(kw, "gid")) {
		kgid_t k = make_kgid(&init_user_ns, num);

		if (!gid_valid(k))
			goto bad;
		if (a->n_gid < NEMCLASS_ACL_MAX_ENTRY)
			a->gids[a->n_gid++] = k;
		else
			pr_warn_ratelimited("acl: gid cap reached, dropping %lu\n", num);
	} else {
		goto bad;
	}
	return;
bad:
	pr_warn_ratelimited("acl: ignoring malformed line: '%s'\n", line);
}

/* Build a fresh snapshot from a NUL-terminated buffer. */
static struct nemclass_acl *nemclass_acl_build(char *buf)
{
	struct nemclass_acl *a;
	char *cur = buf, *line;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return ERR_PTR(-ENOMEM);
	a->uids = kmalloc_array(NEMCLASS_ACL_MAX_ENTRY, sizeof(kuid_t), GFP_KERNEL);
	a->gids = kmalloc_array(NEMCLASS_ACL_MAX_ENTRY, sizeof(kgid_t), GFP_KERNEL);
	if (!a->uids || !a->gids) {
		nemclass_acl_free(a);
		return ERR_PTR(-ENOMEM);
	}

	while ((line = strsep(&cur, "\n")) != NULL)
		nemclass_acl_parse_line(a, line);

	return a;
}

/*
 * Re-read the config and, if it changed since last time (or `force`), publish a
 * new allowlist. Runs only in process context (init + workqueue). Returns 0 on
 * "up to date or reloaded", or a negative errno the caller may ignore.
 */
static int nemclass_acl_reload(bool force)
{
	struct file *f;
	struct inode *inode;
	struct nemclass_acl *a;
	struct timespec64 mt;
	char *buf;
	loff_t pos = 0;
	ssize_t n;
	u64 size;
	unsigned long ino;
	int ret = 0;

	mutex_lock(&nemclass_acl_reload_lock);

	f = filp_open(access_config, O_RDONLY, 0);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		/* Transition to "no config" once; stay quiet on repeated polls. */
		if (force || nemclass_acl_fp.valid) {
			nemclass_acl_fp.valid = false;
			nemclass_acl_publish(NULL);
			scnprintf(nemclass_acl_status, sizeof(nemclass_acl_status),
				  "config %s unavailable (%d): deny-all except CAP_SYS_ADMIN",
				  access_config, ret);
			pr_warn("acl: %s\n", nemclass_acl_status);
		}
		goto out;
	}

	inode = file_inode(f);
	mt = inode_get_mtime(inode);
	size = i_size_read(inode);
	ino = inode->i_ino;

	if (!force && nemclass_acl_fp.valid &&
	    nemclass_acl_fp.size == size &&
	    nemclass_acl_fp.mtime_sec == mt.tv_sec &&
	    nemclass_acl_fp.mtime_nsec == mt.tv_nsec &&
	    nemclass_acl_fp.ino == ino) {
		filp_close(f, NULL);		/* unchanged: nothing to do */
		goto out;
	}

	buf = kvmalloc(NEMCLASS_ACL_FILE_MAX + 1, GFP_KERNEL);
	if (!buf) {
		filp_close(f, NULL);
		ret = -ENOMEM;
		goto out;
	}

	n = kernel_read(f, buf, NEMCLASS_ACL_FILE_MAX, &pos);
	filp_close(f, NULL);
	if (n < 0) {
		kvfree(buf);
		ret = n;
		goto out;
	}
	buf[n] = '\0';

	a = nemclass_acl_build(buf);
	kvfree(buf);
	if (IS_ERR(a)) {
		ret = PTR_ERR(a);
		goto out;
	}

	nemclass_acl_publish(a);
	nemclass_acl_fp.valid		= true;
	nemclass_acl_fp.size		= size;
	nemclass_acl_fp.mtime_sec	= mt.tv_sec;
	nemclass_acl_fp.mtime_nsec	= mt.tv_nsec;
	nemclass_acl_fp.ino		= ino;
	scnprintf(nemclass_acl_status, sizeof(nemclass_acl_status),
		  "loaded %u uid + %u gid from %s", a->n_uid, a->n_gid, access_config);
	pr_info("acl: %s\n", nemclass_acl_status);

out:
	mutex_unlock(&nemclass_acl_reload_lock);
	return ret;
}

static void nemclass_acl_poll(struct work_struct *w)
{
	unsigned int ms = READ_ONCE(access_poll_ms);

	nemclass_acl_reload(false);
	if (ms)
		schedule_delayed_work(&nemclass_acl_work, msecs_to_jiffies(ms));
}

/*
 * Open-time gate. 0 => allowed, -EACCES => denied. CAP_SYS_ADMIN is always
 * allowed so an empty/missing policy can never lock out the administrator.
 */
int nemclass_access_check_open(void)
{
	const struct nemclass_acl *a;
	kuid_t euid = current_euid();
	int ret = -EACCES;
	unsigned int i;

	if (capable(CAP_SYS_ADMIN))
		return 0;

	rcu_read_lock();
	a = rcu_dereference(nemclass_acl);
	if (a) {
		for (i = 0; i < a->n_uid; i++) {
			if (uid_eq(a->uids[i], euid)) {
				ret = 0;
				goto out;
			}
		}
		for (i = 0; i < a->n_gid; i++) {
			if (in_egroup_p(a->gids[i])) {
				ret = 0;
				goto out;
			}
		}
	}
out:
	rcu_read_unlock();
	if (ret)
		pr_warn_ratelimited("open denied for uid %u (not listed in %s)\n",
				    from_kuid(&init_user_ns, euid), access_config);
	return ret;
}

/* Backing show() for /proc/nemclass/acl. */
int nemclass_access_proc_show(struct seq_file *m, void *v)
{
	const struct nemclass_acl *a;
	unsigned int i;

	mutex_lock(&nemclass_acl_reload_lock);
	seq_printf(m, "config:  %s\n", access_config);
	seq_printf(m, "poll_ms: %u\n", access_poll_ms);
	seq_printf(m, "status:  %s\n", nemclass_acl_status);
	mutex_unlock(&nemclass_acl_reload_lock);

	seq_puts(m, "allow:   CAP_SYS_ADMIN (always)\n");

	rcu_read_lock();
	a = rcu_dereference(nemclass_acl);
	if (!a || (!a->n_uid && !a->n_gid)) {
		seq_puts(m, "         (no uid/gid entries — non-root denied)\n");
	} else {
		for (i = 0; i < a->n_uid; i++)
			seq_printf(m, "allow:   uid %u\n",
				   from_kuid(&init_user_ns, a->uids[i]));
		for (i = 0; i < a->n_gid; i++)
			seq_printf(m, "allow:   gid %u\n",
				   from_kgid(&init_user_ns, a->gids[i]));
	}
	rcu_read_unlock();
	return 0;
}

void nemclass_access_init(void)
{
	INIT_DELAYED_WORK(&nemclass_acl_work, nemclass_acl_poll);
	/* Synchronous first load so the policy is in force before /proc appears. */
	nemclass_acl_reload(true);
	if (access_poll_ms)
		schedule_delayed_work(&nemclass_acl_work,
				      msecs_to_jiffies(access_poll_ms));
}

void nemclass_access_exit(void)
{
	cancel_delayed_work_sync(&nemclass_acl_work);
	mutex_lock(&nemclass_acl_reload_lock);
	nemclass_acl_publish(NULL);
	mutex_unlock(&nemclass_acl_reload_lock);
	/* Wait for outstanding call_rcu() frees before our text is unloaded. */
	rcu_barrier();
}
