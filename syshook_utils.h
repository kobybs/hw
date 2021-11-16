#ifndef SYS_HOOK_H
#define SYS_HOOK_H

#include <linux/ftrace.h>

struct sys_hook {
    void** orig_func_pointer;
    void* hook_func;
    int sys_entry;
};

int set_sys_hooks(struct sys_hook *hooks, size_t count);
int undo_sys_hooks(struct sys_hook *hooks, size_t count);

#endif /* SYS_HOOK_H */

