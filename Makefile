obj-m += mymod.o
mymod-y := hellomod.o ftrace_utils.o syshook_utils.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean