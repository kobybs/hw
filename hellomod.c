#define MODULE
#define LINUX
#define __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void)
{
    printk("Hello World\n");
    return 0;
}

void cleanup_module(void)
{       
    printk("Module Removed\n");
}

