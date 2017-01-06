EXTRA_CFLAGS := -I$(src)/../include

obj-m += sch_wxx.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
			
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
