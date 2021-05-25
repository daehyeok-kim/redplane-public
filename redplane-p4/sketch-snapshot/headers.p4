#ifndef _HEADERS_
#define _HEADERS_

#include "types.p4"

const PortId_t CPU_PORT = 320;
const PortId_t DEFAULT_STORE_PORT = 8;
//const PortId_t CPU_PORT = 64;
//const PortId_t DEFAULT_STORE_PORT = 1;

const ether_type_t ETHERTYPE_IPV4 = 0x0800;
const ether_type_t ETHERTYPE_TO_CPU = 0xBF01;

const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

const mirror_type_t MIRROR_TYPE_E2E = 2;

const bit<48> LEASE_PERIOD = 100000000000; // 5 secs
const bit<48> TIMEOUT = 1000000; // 1 msec
const bit<16> MAX_SEQ_NUM = 65533;
const bit<16> SWITCH_UDP_PORT = 4000;
const bit<16> STORE_UDP_PORT = 8000;

const pkt_type_t PKT_TYPE_NORMAL = 0; // Normal packets (just coming in);
const pkt_type_t PKT_TYPE_EGR_MIRROR = 1; // Transaction for logging

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header tstamp_h{
    bit<48> in_time;
    bit<48> out_time;
}

header redplane_req_h {
    req_type_t req_type; //1
    bit<16> seq_num; // 2
    flow_key_t flow_key; //1
    flow_value_t values; //12
}

const bit<16> REDPLANE_REQ_IP_LEN = 20 + 8 + 16;
const bit<16> REDPLANE_REQ_UDP_LEN = 8 + 16;

header redplane_ack_h {
    ack_type_t ack_type; // 1
    bit<16> seq_num; // 2
    flow_key_t flow_key; // 1
}
const bit<16> REDPLANE_ACK_IP_LEN = 20 + 8 + 4;

header redplane_flow_value_h {
    flow_value_t values;
}

header egr_mirror_h {
    pkt_type_t pkt_type;
    bit<48> tstamp;
    @padding
    bit<7> pad;
    bit<1> is_first_time;
}

header bridged_md_h {
    pkt_type_t pkt_type; //8
    PortId_t store_egress_port; //9
    PortId_t original_port; //9
    bit<1> is_write;
    @padding
    bit<5> pad;
}

struct ingress_headers_t {
    pktgen_timer_header_t pktgen_hdr;
    bridged_md_h bridged_md;
    ethernet_h cpu_ethernet;
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    ipv4_h redplane_ipv4;
    udp_h redplane_udp;
    redplane_req_h redplane_req; 
    redplane_ack_h redplane_ack; 
    redplane_flow_value_h redplane_values;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    tstamp_h tstamp;
}

struct egress_headers_t {
    ethernet_h ethernet;
    ipv4_h redplane_ipv4;
    udp_h redplane_udp;
    redplane_req_h redplane_req; 
    redplane_ack_h redplane_ack; 
    redplane_flow_value_h redplane_values;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}

struct ingress_metadata_t {
    bit<2> hashed_key;
    bool is_renew_req;
    bool lease_expired;
    nat_meta_t nat_meta;
    // snapshot
    bit<32> update_val;
    snapshot_meta_t active_buffer1;
    snapshot_meta_t active_buffer2;
    snapshot_meta_t active_buffer3;
    snapshot_meta_t last_updated_buffer_for_index1;
    snapshot_meta_t last_updated_buffer_for_index2;
    snapshot_meta_t last_updated_buffer_for_index3;

    // checksum stuff
    bool ipv4_checksum_err;
    bool checksum_update_ipv4;
    bool checksum_update_redplane_ipv4;
    bool checksum_update_tcp;
    bit<16> checksum_tcp_tmp;
    flow_key_t flow_key;
    bit<32> new_lease_expire_time;
    bit<32> current_time;

    //SKETCH
    bit<8> sketch_key1;
    bit<8> sketch_key2;
    bit<8> sketch_key3;
}

struct egress_metadata_t {
    bridged_md_h bridged_md;
    bit<48> tstamp;
    bit<16> time_diff_hi;
    bit<16> time_diff_lo;
    MirrorId_t egr_mir_ses;
    pkt_type_t pkt_type;
    bool is_acked_req;
    bool is_logged_req;
    bit<16> seq_same;
    bit<16> last_sent;
    bit<16> last_acked;
    bit<16> seq_diff;
    bit<16> seq_diff1;
    bit<16> seq_diff2;
    bit<16> cur_seq_num;
    bit<1> is_first_time;
    // checksum stuff
    bool checksum_err_ipv4;
    flow_key_t flow_key;
}

#endif /* _HEADERS_ */
