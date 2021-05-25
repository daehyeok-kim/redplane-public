#pragma once

#include <dirent.h>
#include <infiniband/verbs.h>
#include <string>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "common.h"

namespace redplane
{
static constexpr uint16_t kIPEtherType = 0x800;
static constexpr uint16_t kIPHdrProtocol = 0x11;
static constexpr uint16_t kIPHdrTCPProtocol = 0x06;
static std::string mac_to_string(const uint8_t *mac)
{
    std::ostringstream ret;
    for (size_t i = 0; i < 6; i++)
    {
        ret << std::hex << static_cast<uint32_t>(mac[i]);
        if (i != 5)
            ret << ":";
    }
    return ret.str();
}

/// Get the network-byte-order IPv4 address from a human-readable IP string
static uint32_t ipv4_from_str(const char *ip)
{
    uint32_t addr;
    int ret = inet_pton(AF_INET, ip, &addr);
    rt_assert(ret == 1, "inet_pton() failed for " + std::string(ip));
    return addr;
}

/// Convert a network-byte-order IPv4 address to a human-readable IP string
static std::string ipv4_to_string(uint32_t ipv4_addr)
{
    char str[INET_ADDRSTRLEN];
    const char *ret = inet_ntop(AF_INET, &ipv4_addr, str, sizeof(str));
    rt_assert(ret == str, "inet_ntop failed");
    str[INET_ADDRSTRLEN - 1] = 0; // Null-terminate
    return str;
}

static uint32_t get_interface_ipv4_addr(std::string interface)
{
    struct ifaddrs *ifaddr, *ifa;
    rt_assert(getifaddrs(&ifaddr) == 0);
    uint32_t ipv4_addr = 0;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (strcmp(ifa->ifa_name, interface.c_str()) != 0)
            continue;

        // We might get the same interface multiple times with different sa_family
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET)
        {
            continue;
        }

        auto sin_addr = reinterpret_cast<sockaddr_in *>(ifa->ifa_addr);
        ipv4_addr = ntohl(*reinterpret_cast<uint32_t *>(&sin_addr->sin_addr));
    }

    rt_assert(ipv4_addr != 0,
              std::string("Failed to find interface ") + interface);

    freeifaddrs(ifaddr);
    return ipv4_addr;
}

struct eth_hdr_t
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;

    std::string to_string() const
    {
        std::ostringstream ret;
        ret << "[ETH: dst " << mac_to_string(dst_mac) << ", src "
            << mac_to_string(src_mac) << ", eth_type "
            << std::to_string(ntohs(eth_type)) << "]";
        return ret.str();
    }
} __attribute__((packed));

struct ipv4_hdr_t
{
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t ecn : 2;
    uint8_t dscp : 6;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t src_ip;
    uint32_t dst_ip;

    std::string to_string() const
    {
        std::ostringstream ret;
        ret << "[IPv4: ihl " << std::to_string(ihl) << ", version "
            << std::to_string(version) << ", ecn " << std::to_string(ecn)
            << ", tot_len " << std::to_string(ntohs(tot_len)) << ", id "
            << std::to_string(ntohs(id)) << ", frag_off "
            << std::to_string(ntohs(frag_off)) << ", ttl " << std::to_string(ttl)
            << ", protocol " << std::to_string(protocol) << ", check "
            << std::to_string(check) << ", src IP " << ipv4_to_string(src_ip)
            << ", dst IP " << ipv4_to_string(dst_ip) << "]";
        return ret.str();
    }
} __attribute__((packed));

struct udp_hdr_t
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t check;

    std::string to_string() const
    {
        std::ostringstream ret;
        ret << "[UDP: src_port " << std::to_string(ntohs(src_port)) << ", dst_port "
            << std::to_string(ntohs(dst_port)) << ", len "
            << std::to_string(ntohs(len)) << ", check " << std::to_string(check)
            << "]";
        return ret.str();
    }
} __attribute__((packed));

struct tcp_hdr_t
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
    std::string to_string() const
    {
        std::ostringstream ret;
        ret << "[TCP: src_port " << std::to_string(ntohs(src_port)) << ", dst_port "
            << std::to_string(ntohs(dst_port))  
            << "]";
        return ret.str();
    }
} __attribute__((packed));


class RawTransport
{
public:
    static constexpr size_t kPostlist = 2048; ///< Maximum SEND postlist
    static constexpr size_t kNumRxRingEntries = 2048;
    static constexpr size_t kRQDepth = kNumRxRingEntries;
    static constexpr size_t kSQDepth = kPostlist;
    static constexpr size_t kMTU = 4096;
    static constexpr size_t kMaxInline = 0; ///< Maximum send wr inline data
    static constexpr size_t kRecvSize = kMTU;
    static constexpr size_t kRingSize = (kNumRxRingEntries * kRecvSize);
    static constexpr size_t kSendRingSize = (kSQDepth * kRecvSize);
    static constexpr size_t kRecvSlack = 32;
    static constexpr size_t kMaxRoutingInfoSize = 48; ///< Space for routing info
    static constexpr size_t kInetHdrsTotSize = sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t);

    struct RoutingInfo
    {
        uint8_t buf[kMaxRoutingInfoSize];
    };

    RawTransport(uint16_t udp_port, uint8_t num_phy_ports, uint8_t *send_buf, size_t send_buf_size);
    ~RawTransport();

    uint8_t **getRxRing() { return rx_ring; }
    void post_recvs(size_t num_recvs);
    size_t rx_burst();
    void tx_one(uint64_t buf_addr, size_t pkt_size);
    void tx_burst(const std::vector<uint64_t> buf_addr, const std::vector<uint32_t> pkt_size, const size_t pkt_count);
    void fill_local_routing_info(RoutingInfo *routing_info) const;

private:
    class VerbsResolve
    {
    public:
        int device_id = -1;                   ///< Device index in list of verbs devices
        struct ibv_context *ib_ctx = nullptr; ///< The verbs device context
        uint8_t dev_port_id = 0;              ///< 1-based port ID in device. 0 is invalid.
        size_t bandwidth = 0;                 ///< Link bandwidth in bytes per second
        std::string ibdev_name;               ///< Verbs device name (e.g., mlx5_0)
        std::string netdev_name;              ///< Verbs device name (e.g., ens2)
        uint32_t ipv4_addr;                   ///< The port's IPv4 address in host-byte order
        uint8_t mac_addr[6];                  ///< The port's MAC address
    } resolve;

    uint8_t *buf;
    uint8_t *rx_ring[kNumRxRingEntries];

    struct ibv_pd *pd = nullptr;
    struct ibv_qp *qp = nullptr; 
    struct ibv_cq *send_cq = nullptr;
    struct ibv_cq *recv_cq = nullptr;
    struct ibv_exp_flow *recv_flow;

    // SEND
    struct ibv_send_wr send_wr[kPostlist + 1]; 
    struct ibv_sge send_sgl[kPostlist][2];     
    uint8_t *send_buf;
    size_t send_buf_size;
    struct ibv_mr *send_buf_mr;
    size_t send_head = 0;

    // RECV
    const uint16_t rx_flow_udp_port;
    size_t recvs_to_post = 0; 
    size_t recv_head = 0;    
    struct ibv_mr *recv_buf_mr;

    struct ibv_recv_wr recv_wr[kRQDepth];
    struct ibv_sge recv_sgl[kRQDepth];
    struct ibv_wc recv_wc[kRQDepth];

    void init_verbs_structs();
    void init_basic_qp();

    void install_flow_rule();
    void install_flow_rule_any();
    void common_resolve_phy_port(uint8_t phy_port, size_t mtu);

    void init_recvs();
    void init_sends(uint8_t *send_buf, size_t send_buf_size);
};

struct MemRegInfo
{
    void *transport_mr; ///< The transport-specific memory region (eg, ibv_mr)
    uint32_t lkey;      ///< The lkey of the memory region

    MemRegInfo(void *transport_mr, uint32_t lkey)
        : transport_mr(transport_mr), lkey(lkey) {}

    MemRegInfo() : transport_mr(nullptr), lkey(0xffffffff) {}
};

static size_t enum_to_mtu(enum ibv_mtu mtu)
{
    switch (mtu)
    {
    case IBV_MTU_256:
        return 256;
    case IBV_MTU_512:
        return 512;
    case IBV_MTU_1024:
        return 1024;
    case IBV_MTU_2048:
        return 2048;
    case IBV_MTU_4096:
        return 4096;
    default:
        return 0;
    }
}

static std::string link_layer_str(uint8_t link_layer)
{
    switch (link_layer)
    {
    case IBV_LINK_LAYER_UNSPECIFIED:
        return "[Unspecified]";
    case IBV_LINK_LAYER_INFINIBAND:
        return "[InfiniBand]";
    case IBV_LINK_LAYER_ETHERNET:
        return "[Ethernet]";
    default:
        return "[Invalid]";
    }
}

static inline void poll_cq_one_helper(struct ibv_cq *cq)
{
    struct ibv_wc wc;
    size_t num_tries = 0;
    while (ibv_poll_cq(cq, 1, &wc) == 0)
    {
        // Do nothing while we have no CQE or poll_cq error
        if (1)
        {
            num_tries++;
            if (unlikely(num_tries == GB(1)))
            {
                fprintf(stderr, "RawTransport: Warning. Stuck in poll_cq().");
                num_tries = 0;
            }
        }
    }
    if (unlikely(wc.status != 0))
    {
        fprintf(stderr, "RawTransport: Fatal error. Bad wc status %d.\n", wc.status);
        assert(false);
        exit(-1);
    }
}

/// Return the net interface for a verbs device (e.g., mlx5_0 -> ens2)
static std::string ibdev2netdev(std::string ibdev_name)
{
    std::string dev_dir = "/sys/class/infiniband/" + ibdev_name + "/device/net";

    std::vector<std::string> net_ifaces;
    DIR *dp;
    struct dirent *dirp;
    dp = opendir(dev_dir.c_str());
    rt_assert(dp != nullptr, "Failed to open directory " + dev_dir);

    while (true)
    {
        dirp = readdir(dp);
        if (dirp == nullptr)
            break;

        if (strcmp(dirp->d_name, ".") == 0)
            continue;
        if (strcmp(dirp->d_name, "..") == 0)
            continue;
        net_ifaces.push_back(std::string(dirp->d_name));
    }
    closedir(dp);

    rt_assert(net_ifaces.size() > 0, "Directory " + dev_dir + " is empty");
    return net_ifaces[0];
}

static void fill_interface_mac(std::string interface, uint8_t *mac)
{
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);

    int ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    rt_assert(ret == 0, "MAC address IOCTL failed");
    close(fd);

    for (size_t i = 0; i < 6; i++)
    {
        mac[i] = static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[i]);
    }
}

struct eth_routing_info_t
{
    uint8_t mac[6];
    uint32_t ipv4_addr;
    uint16_t udp_port;

    std::string to_string()
    {
        std::ostringstream ret;
        ret << "[MAC " << mac_to_string(mac) << ", IP " << ipv4_to_string(ipv4_addr)
            << ", UDP port " << std::to_string(udp_port) << "]";

        return std::string(ret.str());
    }
};

} // namespace redplane
