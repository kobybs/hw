struct sys_hook {
    void** orig_func_pointer;
    void* hook_func;
    int sys_entry;
};

void set_page_rw(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}

void set_page_ro(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
}

int set_sys_hooks(struct sys_hook *hooks, size_t count){
    int i;
    unsigned long **p_sys_call_table = (void *) kallsyms_lookup_name("sys_call_table");

    if(!p_sys_call_table){
        printk("failed to get sys_call_table addres");
        return -1;
    }

    set_page_rw((unsigned long)p_sys_call_table);

    for (i = 0; i < count; i++) {
        *((unsigned long*) hooks[i].orig_func_pointer) = (unsigned long) p_sys_call_table[hooks[i].sys_entry];
        p_sys_call_table[hooks[i].sys_entry] = (void*)hooks[i].hook_func;
	}

    return 0;
}

int undo_sys_hooks(struct sys_hook *hooks, size_t count)
{
    int i;
    unsigned long **p_sys_call_table = (void *) kallsyms_lookup_name("sys_call_table");

    if(!p_sys_call_table){
        printk("failed to get sys_call_table addres");
        return -1;
    }

    for (i = 0; i < count; i++) {
        p_sys_call_table[hooks[i].sys_entry] = (void*) *((unsigned long*) hooks[i].orig_func_pointer);
	}
    set_page_ro((unsigned long)p_sys_call_table);

    return 0;
}

