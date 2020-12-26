arm-linux-gnueabi-as syscalls.s -o syscalls.o
arm-linux-gnueabi-gcc -c sniffer.c -fno-stack-protector
arm-linux-gnueabi-gcc -nostdlib sniffer.o syscalls.o -o sniffer -fno-stack-protector
