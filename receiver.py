#!/usr/bin/python3

from scapy.all import *

import socket

HOST = '0.0.0.0'
PORT = 4444

p = b''

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1)
            if not data:
                break

            # Contruct packet. Packet may be greater than tcp max packet size
            p += data
            # Look for special delimeter between packets
            if p[-7:] == b"-DELIM-":
                #Strip off delimeter
                p=p[:-7]
                # Parse full packet
                print(Ether(p).summary())
                # Reset packet
                p = b''
