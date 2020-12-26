arm-linux-gnueabi-as hello_tcp.s -o hello_tcp.o
arm-linux-gnueabi-ld hello_tcp.o -o hello_tcp

arm-linux-gnueabi-as old_sniffer.s -o old_sniffer.o
arm-linux-gnueabi-ld old_sniffer.o -o old_sniffer
