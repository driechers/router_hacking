# Router Hacking

This is just some fun I had after i found how to execute code on my router. My router is running a 2.6 kernel (kinda pathetic) and an old version of libc. Cross compiling was going to be a pain so for fun I decided to whip out the assembler and try to make some utilities. 

hello\_tcp
------------------------------------------------------
This is just a hello world tcp client. The message being sent is hard coded in the data segment but can be easily turned into other utilities

sniffer
------------------------------------------------------
This is supposed to be a packet sniffer. The router does not have tcpdump or other sniffing utilities so I created this to try to sniff network traffic using a raw ethernet socket and a tcp client socket to stream captured traffic to a network host. For some reason though it crashes my router and I need to power cycle to recover.
