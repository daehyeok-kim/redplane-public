#ifndef _TYPES_
#define _TYPES_

typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;
typedef bit<32> ipv4_addr_t;
typedef bit<8> ip_protocol_t;
typedef bit<16> udp_port_t;

typedef bit<3> mirror_type_t;
typedef bit<8> pkt_type_t;

enum bit<8> req_type_t {
    LEASE_NEW_REQ = 0x0, 
    LEASE_RENEW_REQ = 0x1,
    LEASE_NEW_ACK = 0x3,
    LEASE_RENEW_ACK = 0x4, 
    LEASE_MIGRATE_ACK = 0x5
}

enum bit<8> ack_type_t {
    LEASE_NEW_ACK = 0x0,
    LEASE_RENEW_ACK = 0x1, 
    LEASE_MIGRATE_ACK = 0x2
}

// NAT 
// COMPILER: this structure should be generated by redplane compiler or given as a user-input.
struct flow_key_t {
    ipv4_addr_t ip_addr;
    bit<16> port;
}

struct flow_value_t {
    ipv4_addr_t ip_addr;
    bit<16> port; 
}

struct nat_meta_t {
    bool  is_ext;
}

#endif /* _TYPES_ */