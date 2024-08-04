#! /usr/bin/python

from ctypes import *
import socket
import struct


class IP(Structure):
    _fields_ = [
        ("version",          c_ubyte, 4),
        ("ihl",              c_ubyte, 4),
        ("tos",              c_ubyte, 8),
        ("len",              c_ushort,16),
        ("id",               c_ushort,16),
        ("offset",           c_ushort,16),
        ("ttl",              c_ubyte, 8),
        ("protocol_num",     c_ubyte, 8),
        ("sum",              c_ushort,16),
        ("src",              c_uint32,32),
        ("dst",              c_uint32,32)
        ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {
                1:"ICMP",
                6:"TCP",
                17:"UDP"
                }
        
        # Human Readble form
        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("!I",self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

#s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("eth0", 0))

try:
    while True:
        # Reading Packet
        resp = s.recvfrom(65565)[0]
        #print(resp)
        #print(IP)
        
        # Creating an IP header from the first 20 bytes of the buffer
        ip = IP(resp[14:])
        #print("RAW: ", ip)

        # Print out protocol and the host
        print("Protocol: %s %s -> %s" % (ip.protocol, ip.src_address, ip.dst_address))
except KeyboardInterrupt:
    pass

