#!/usr/bin/python3

import socket
import struct
import binascii

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

while True:
    pkt = s.recvfrom(2048)
    
    #ethernet header 14bytes
    ethhead = pkt[0][0:14]

    eth = struct.unpack("!6s6s2s",ethhead)

    
    print("-------ethernet frame----------")

    #宛先MAC
    print("destination MAC: {}".format(binascii.hexlify(eth[0]).decode()))
    #送信元MAC
    print("Source MAC: {}".format(binascii.hexlify(eth[1]).decode()))

    binascii.hexlify(eth[2])

    print('\n')
    #ipheader-part 14bytes + 20bytes
    ipheader = pkt[0][14:34] 

    
    ip_hdr = struct.unpack("!8sB3s4s4s",ipheader)
    print("-----------IP------------------")
    print("TTL: {}".format(ip_hdr[1]))
    print("Source IP: {}".format(socket.inet_ntoa(ip_hdr[3])))
    print("Destination IP: {}".format(socket.inet_ntoa(ip_hdr[4])))
    print('\n')
    
    print("---------TCP----------")
    #tcp header 20 bytes
    tcpheader = pkt[0][34:54]
    
    #tcp_hdr = struct.unpack("!HH16s",tcpheader)
    tcp_hdr = struct.unpack("!HH9ss6s",tcpheader)
    print("Source Port: {}".format(tcp_hdr[0]))
    print("Destination port: {}".format(tcp_hdr[1]))
    print("Flag: {}".format(binascii.hexlify(tcp_hdr[3]).decode()))
    print(pkt[0][54:].decode('utf-8', errors='ignore'))


    
