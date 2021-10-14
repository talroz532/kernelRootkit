# kernelRootkit
A simple Linux Kernel Rootkit to hide process from linux commands: 'ps' 'ls'

 insert the module:
 `sudo insmod lkm_example.ko <PID>`
 
 remove the module:
 `sudo rmmod lkm_example`
