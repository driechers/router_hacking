arm-linux-gnueabi-as hello_tcp.s -o hello_tcp.o
arm-linux-gnueabi-ld hello_tcp.o -o hello_tcp

arm-linux-gnueabi-as sniffer.s -o sniffer.o
arm-linux-gnueabi-ld sniffer.o -o sniffer
