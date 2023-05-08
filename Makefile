obj-m += minifw.o
PWD := $(CURDIR)
CFLAGS += -lc
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

re :
	$(MAKE) clean
	$(MAKE) 
