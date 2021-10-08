obj-m += rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o functions functions.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm functions
