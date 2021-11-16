#ifndef FTRACE_HOOK_H
#define FTRACE_HOOK_H

#include <linux/ftrace.h>

struct ftrace_hook {
    void** orig_func_pointer;
    void* hook_func;
    struct ftrace_ops ops;
};

int undo_ftrace_hook(struct ftrace_hook* hook);
int set_ftrace_hook(char* name, struct ftrace_hook* hook);

#endif /* FTRACE_HOOK_H */

