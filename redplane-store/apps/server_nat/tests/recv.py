#!/usr/bin/python
######################################################
#   Copyright (C) Microsoft. All rights reserved.    #
######################################################

import os
import sys
import random

if os.getuid() !=0:
    print """
ERROR: This script requires root privileges.
       Use 'sudo' to run it.
"""
    quit()

from scapy.all import *
######### Redplane packet definition ###########
req_type_enum = {0x0: "LEASE_NEW_REQ",       0x1: "LEASE_RENEW_REQ"}
ack_type_enum = {0x0: "LEASE_NEW_ACK", 0x1: "LEASE_RENEW_ACK",
                 0x2: "LEASE_MIGRATE_ACK"}


class RedplaneAck (Packet):
    name = "RedPlane ACK header"
    fields_desc = [BitEnumField("ack_type",       0, 8, ack_type_enum),
                   BitField("seq_num",           0, 16),
                   IPField("src_addr_k",           None),
                   IPField("dst_addr_k",           None),
                   ShortField("src_port_k", None),
                   ShortField("dst_port_k", None),
                   ByteField("protocol_k", None)
                   ]


class RedplaneValue (Packet):
    name = "RedPlane State header"
    fields_desc = [
        IPField("dst_addr_v",           None),
        ShortField("dst_port_v", None)
    ]


bind_layers(UDP, RedplaneAck, dport=4000)
bind_layers(RedplaneAck, RedplaneValue, ack_type=0x2)
bind_layers(RedplaneValue, IP)
bind_layers(RedplaneAck, IP, ack_type=0x0)
bind_layers(RedplaneAck, IP, ack_type=0x1)


class RedplaneReq (Packet):
    name = "RedPlane transaction header"
    fields_desc = [BitEnumField("req_type",       0, 8, req_type_enum),
                   BitField("seq_num",           0, 16),
                   IPField("src_addr_k",           None),
                   IPField("dst_addr_k",           None),
                   ShortField("src_port_k", None),
                   ShortField("dst_port_k", None),
                   ByteField("protocol_k", None),
                   IPField("dst_addr_v",           None),
                   ShortField("dst_port_v", None)
                   ]


bind_layers(UDP, RedplaneReq, sport=4000)
bind_layers(RedplaneReq, IP)

def print_pkt (pkt):
    print(pkt.show())

if __name__ == "__main__":
    sniff (iface="ens1", filter='udp dst port 4000', prn=print_pkt)