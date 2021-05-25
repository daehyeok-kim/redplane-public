#!/usr/bin/python
######################################################
#   Copyright (C) Microsoft. All rights reserved.    #
######################################################

import os
import sys
import random
import threading

if os.getuid() !=0:
    print """
ERROR: This script requires root privileges.
       Use 'sudo' to run it.
"""
    quit()

from scapy.all import *

flow_vals = {}
NUM_TEST_KEYS = 1000

txn_type_enum = { 0x0: "LEASE_NEW_REQ",       0x1: "LEASE_RENEW_REQ",
                        0x2: "LEASE_NEW_ACK", 0x3: "LEASE_RENEW_ACK",
                        0x4: "LEASE_MIGRATE_ACK" }
class RedplaneAck (Packet):
    name = "RedPlane ACK header"
    fields_desc = [ BitEnumField("ack_type",       0, 8, txn_type_enum),
                    BitField("seq_num",           0, 32),
                    BitField("lease_expire_time",           0, 32),
                    BitField("flow_key",           0, 104)
    ]
class RedplaneState (Packet):
    name = "RedPlane State header"
    fields_desc = [ BitField("State",       0, 32)
                   ]

bind_layers(UDP, RedplaneAck, dport=4000)
bind_layers(RedplaneAck, RedplaneState, ack_type=0x4)
bind_layers(RedplaneState, IP)
bind_layers(RedplaneAck, IP, ack_type=0x2)
bind_layers(RedplaneAck, IP, ack_type=0x3)

class RedplaneTxn (Packet):
    name = "RedPlane transaction header"
    fields_desc = [ BitEnumField("txn_type",       0, 8, txn_type_enum),
                    BitField("seq_num",           0, 32),
                    BitField("flow_key",           0, 104),
                    BitField("flow_value",           0, 32)
    ]

bind_layers(UDP, RedplaneTxn, sport=4000)
bind_layers(RedplaneTxn, IP)

# Send txn from a switch to a state store
def send_write_txn (src_ip, dst_ip, dest_port, flow_key, flow_val, txn_type, seq_num, payload_size):
    p = (Ether()/
        IP(dst=dst_ip, src=src_ip)/
        UDP(sport=4000, dport=dest_port)/
        RedplaneTxn(txn_type=txn_type, seq_num=seq_num, flow_key=flow_key, flow_value=flow_val)/
        IP()/
        #TCP()/
        Raw(RandString(size=payload_size)))

    sendp(p, iface="ens1", count = 1)

def send_read_txn (src_ip, dst_ip, dest_port, txn_type, seq_num):
    p = (Ether()/
        IP(dst=dst_ip, src=src_ip)/
        UDP(sport=4000, dport=dest_port)/
        RedplaneTxn(txn_type=txn_type, seq_num=seq_num, flow_key=0))

    sendp(p, iface="ens1", count = 1)

def print_pkt (pkt):
    flow_key = int(pkt[RedplaneAck].flow_key)
    assert(flow_vals[flow_key] == int(pkt[RedplaneState].State))

def sniff_thread():
    sniff (iface="ens1", filter='udp dst port 4000', prn=print_pkt, count = NUM_TEST_KEYS)

if __name__ == "__main__":

    payload_size = int(sys.argv[1])
    flow_keys = []

    print ("LEASE_NEW_REQ")
    # send LEASE_NEW_REQ
    for i in range(0, NUM_TEST_KEYS):
        while True:
            flow_key = random.getrandbits(104)
            if flow_key in flow_keys:
                continue
            flow_keys.append(flow_key)
            break
        send_write_txn ("198.19.10.0","198.19.11.0", 4001, flow_key, 0, 0x0, 0, payload_size)

    print ("LEASE_RENEW_REQ (WRITE)")
    # send LEASE_RENEW_REQ (WRITE)
    accessed = []
    count = 0
    while True:
        idx = random.randint(0, NUM_TEST_KEYS-1)
        if idx in accessed:
            continue
        flow_val = random.getrandbits(32)
        send_write_txn ("198.19.10.0","198.19.11.0", 4001, flow_keys[idx], flow_val, 0x1, 1, payload_size)
        accessed.append(idx)
        flow_vals[flow_keys[idx]] = flow_val
        count = count + 1
        if count == NUM_TEST_KEYS:
            break

    print ("LEASE_NEW_REQ (MIGRATE))")
    ## send LEASE_NEW_REQ (MIGRATE)
    sniff_th = threading.Thread(target=sniff_thread, args=())
    sniff_th.start()
    time.sleep(1)
    for i in range(0, NUM_TEST_KEYS):
        send_write_txn ("198.19.10.0","198.19.11.0", 4001, flow_keys[i], 0, 0x0, 0, payload_size)
    sniff_th.join()
