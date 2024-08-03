#! /usr/bin/python

from ctypes import *
#import ctypes
import socket
import struct


class IP(Structure):
    _fields_ = [
        ("version",          c_ubyte, 4),
        ("ihl",              c_ubyte, 4),
        ("tos",              c_ubyte),
        ("len",              c_ushort),
        ("id",               c_ushort),
        ("offset",           c_ushort),
        ("ttl",              c_ubyte),
        ("protocol_num",     c_ubyte),
        ("sum",              c_ushort),
        ("src",              c_uint32),
        ("dst",              c_uint32)
        ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {
                1:"ICMP",
                6:"TCP",
                17:"UDP",
                142:"Unknown Protocol"
                }
        
        # Human Readble form
        self.src_address = socket.inet_ntoa(struct.pack("!I",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("!I",self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

        print("pp: ", self.protocol_num)

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("eth0", 0))

try:
    while True:
        # Reading Packet
        resp = s.recvfrom(65565)[0]

        # Creating an IP header from the first 20 bytes of the buffer
        ip = IP(resp[:20])
        print("RAW: ", ip)

        # Print out protocol and the host
        print("Protocol: %s %s -> %s" % (ip.protocol_num, ip.src_address, ip.dst_address))
        #print(ip.src)
        #print(ip.src_address)
        #print(ip.dst)
        #print(ip.dst_address)

except KeyboardInterrupt:
    pass

