#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/uprobes.h>
#include <linux/namei.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Thomas Wright");
MODULE_DESCRIPTION("Non-ptrace Debugger Engine via Uprobes + Memory access for nemclass");
MODULE_VERSION("1.0");

static char *target_path = "/tmp/target_bin";
static unsigned long target_offset = 0x1149;

static struct inode *target_inode;
static struct uprobe_consumer uc;

static int uprobe_handler(struct uprobe_consumer *self, struct pt_regs *regs)
{
    pr_info("[Debugger Mod] Target hit instruction! IP: 0x%lx, AX: 0x%lx\n", regs->ip, regs->ax);
    return 0; 
}

static int __init nemclass_mod_init(void)
{
    struct path path;
    int ret;

    pr_info("[Debugger Mod] Initializing non-ptrace debugger module via DKMS\n");

    ret = kern_path(target_path, LOOKUP_FOLLOW, &path);
    if (ret) {
        pr_err("[Debugger Mod] Failed to find target binary path: %d\n", ret);
        return ret;
    }
    target_inode = d_real_inode(path.dentry);
    path_put(&path);

    uc.handler = uprobe_handler;

    ret = uprobe_register(target_inode, target_offset, &uc);
    if (ret) {
        pr_err("[Debugger Mod] Uprobe registration failed: %d\n", ret);
        return ret;
    }

    pr_info("[Debugger Mod] Successfully hooked %s at offset 0x%lx\n", target_path, target_offset);
    return 0;
}

static void __exit nemclass_mod_exit(void)
{
    if (target_inode) {
        uprobe_unregister(target_inode, target_offset, &uc);
    }
    pr_info("[Debugger Mod] Module removed cleanly\n");
}

module_init(nemclass_mod_init);
module_exit(nemclass_mod_exit);