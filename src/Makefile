obj-m += firewall_module.o

all: firewall_module.o firewall_interface.exe

firewall_interface.exe: firewall_interface.c firewall.h
	gcc -o firewall_interface.exe firewall_interface.c

firewall_module.o: firewall_module.c firewall.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -rf fw *.o
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
