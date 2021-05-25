#include "raw_transport/raw_transport.h"

static constexpr size_t kOriginMTU = 2048;
enum class req_type_t: uint8_t {
    LEASE_NEW_REQ = 0x0, 
    LEASE_RENEW_REQ = 0x1, 
};

enum class ack_type_t: uint8_t {
    LEASE_NEW_ACK = 0x0,
    LEASE_RENEW_ACK = 0x1, 
    LEASE_MIGRATE_ACK = 0x2
};

/* NAT NF example */
struct req_flow_key_t 
{
    uint32_t ip_addr;
    uint16_t port;

    bool operator == (const req_flow_key_t &key) const {
      return (ip_addr == key.ip_addr
      && port == key.port);
    }
} __attribute__((packed));

struct req_value_t {
    uint32_t ip_addr;
    uint16_t port;
    bool operator == (const req_value_t &value) const {
      return (ip_addr == value.ip_addr
      && port == value.port);
    }
} __attribute__((packed));

struct hash_fn_t {
    size_t operator()(const req_flow_key_t &key) const
    {
        return (std::hash<uint32_t>()(key.ip_addr)
        ^ std::hash<uint16_t>()(key.port));
    }
    size_t operator()(const req_value_t &value ) const
    {
        return (std::hash<uint32_t>()(value.ip_addr)
        ^ std::hash<uint32_t>()(value.port));
    }
};

struct equal_fn_t {
    bool operator()(const req_flow_key_t &key1, const req_flow_key_t &key2) const
    {
        return (key1.ip_addr == key2.ip_addr
        && key1.port == key2.port); 
    }
    size_t operator()(const req_value_t &value1, const req_value_t &value2 ) const
    {
        return (value1.ip_addr == value2.ip_addr
        && value1.port == value2.port);
    }
};

struct tcp_pkt_t
{
  redplane::eth_hdr_t eth_hdr;
  redplane::ipv4_hdr_t ipv4_hdr;
  redplane::tcp_hdr_t tcp_hdr;
  uint8_t payload[kOriginMTU-sizeof(redplane::ipv4_hdr_t)-sizeof(redplane::tcp_hdr_t)];
} __attribute__((packed));
