#include <sys/mman.h>

#include "raw_transport.h"

namespace redplane
{
RawTransport::RawTransport(uint16_t udp_port, uint8_t num_phy_ports, uint8_t *send_buf, size_t send_buf_size)
    : send_buf(send_buf), send_buf_size(send_buf_size), rx_flow_udp_port(udp_port)
{
    common_resolve_phy_port(num_phy_ports, kMTU);
    init_verbs_structs();
    init_recvs();
    init_sends(send_buf, send_buf_size);
}

RawTransport::~RawTransport()
{
    ibv_exp_destroy_flow(recv_flow);
    ibv_destroy_cq(send_cq);
    ibv_destroy_cq(recv_cq);
    ibv_dealloc_pd(pd);
    ibv_close_device(resolve.ib_ctx);

    munmap(buf, kRingSize);
}

void RawTransport::init_verbs_structs()
{
    assert(resolve.ib_ctx != nullptr && resolve.device_id != -1);

    // Create protection domain, send CQ, and recv CQ
    pd = ibv_alloc_pd(resolve.ib_ctx);
    rt_assert(pd != nullptr, "Failed to allocate PD");

    init_basic_qp();
    if (rx_flow_udp_port != 0) {
        install_flow_rule();
    } else {
        install_flow_rule_any();
    }
}

void RawTransport::init_basic_qp()
{
    struct ibv_exp_cq_init_attr cq_init_attr;
    memset(&cq_init_attr, 0, sizeof(cq_init_attr));
    send_cq = ibv_exp_create_cq(resolve.ib_ctx, kSQDepth, nullptr, nullptr, 0,
                                &cq_init_attr);
    rt_assert(send_cq != nullptr, "Failed to create SEND CQ. Forgot hugepages?");

    recv_cq = ibv_exp_create_cq(resolve.ib_ctx, kRQDepth, nullptr, nullptr, 0,
                                &cq_init_attr);
    rt_assert(send_cq != nullptr, "Failed to create RECV CQ");

    struct ibv_exp_qp_init_attr qp_init_attr;
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.comp_mask = IBV_EXP_QP_INIT_ATTR_PD;

    qp_init_attr.pd = pd;
    qp_init_attr.send_cq = send_cq;
    qp_init_attr.recv_cq = recv_cq;
    qp_init_attr.cap.max_send_wr = kSQDepth;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_wr = kRQDepth;
    qp_init_attr.cap.max_recv_sge = 1;
    qp_init_attr.cap.max_inline_data = kMaxInline;
    qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;

    qp = ibv_exp_create_qp(resolve.ib_ctx, &qp_init_attr);
    rt_assert(qp != nullptr, "Failed to create QP");

    struct ibv_exp_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_INIT;
    qp_attr.port_num = 1;
    rt_assert(ibv_exp_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_PORT) == 0);

    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_RTR;
    rt_assert(ibv_exp_modify_qp(qp, &qp_attr, IBV_QP_STATE) == 0);

    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_RTS;
    rt_assert(ibv_exp_modify_qp(qp, &qp_attr, IBV_QP_STATE) == 0);
}

void RawTransport::install_flow_rule_any()
{
    struct ibv_qp *qp_for_flow = qp;
    assert(qp_for_flow != nullptr);

    fprintf(stderr, "Flow RX UDP port any = %u.\n", rx_flow_udp_port);

    static constexpr size_t rule_sz =
        sizeof(ibv_exp_flow_attr) + sizeof(ibv_exp_flow_spec_eth) +
        sizeof(ibv_exp_flow_spec_ipv4_ext);
     
    uint8_t flow_rule[rule_sz];
    memset(flow_rule, 0, rule_sz);
    uint8_t *buf = flow_rule;

    auto *flow_attr = reinterpret_cast<struct ibv_exp_flow_attr *>(flow_rule);
    flow_attr->type = IBV_EXP_FLOW_ATTR_NORMAL;
    flow_attr->size = rule_sz;
    flow_attr->priority = 0;
    flow_attr->num_of_specs = 2;
    flow_attr->port = 1;
    flow_attr->flags = 0;
    flow_attr->reserved = 0;
    buf += sizeof(struct ibv_exp_flow_attr);

    // Ethernet - filter auto-learning broadcast packets sent by switches
    auto *eth_spec = reinterpret_cast<struct ibv_exp_flow_spec_eth *>(buf);
    eth_spec->type = IBV_EXP_FLOW_SPEC_ETH;
    eth_spec->size = sizeof(struct ibv_exp_flow_spec_eth);
    memcpy(&eth_spec->val.dst_mac, resolve.mac_addr, sizeof(resolve.mac_addr));
    memset(&eth_spec->mask.dst_mac, 0xff, sizeof(resolve.mac_addr));
    buf += sizeof(struct ibv_exp_flow_spec_eth);

    // IPv4 - all wildcard
    auto *spec_ipv4 = reinterpret_cast<struct ibv_exp_flow_spec_ipv4_ext *>(buf);
    spec_ipv4->type = IBV_EXP_FLOW_SPEC_IPV4_EXT;
    spec_ipv4->size = sizeof(struct ibv_exp_flow_spec_ipv4_ext);
    buf += sizeof(struct ibv_exp_flow_spec_ipv4_ext);

    recv_flow = ibv_exp_create_flow(qp_for_flow, flow_attr);
    rt_assert(recv_flow != nullptr, "Failed to create RECV flow");
}

void RawTransport::install_flow_rule()
{
    struct ibv_qp *qp_for_flow = qp;
    assert(qp_for_flow != nullptr);

    fprintf(stderr, "Flow RX UDP port = %u.\n", rx_flow_udp_port);

    static constexpr size_t rule_sz =
        sizeof(ibv_exp_flow_attr) + sizeof(ibv_exp_flow_spec_eth) +
        sizeof(ibv_exp_flow_spec_ipv4_ext) + sizeof(ibv_exp_flow_spec_tcp_udp);
     
    uint8_t flow_rule[rule_sz];
    memset(flow_rule, 0, rule_sz);
    uint8_t *buf = flow_rule;

    auto *flow_attr = reinterpret_cast<struct ibv_exp_flow_attr *>(flow_rule);
    flow_attr->type = IBV_EXP_FLOW_ATTR_NORMAL;
    flow_attr->size = rule_sz;
    flow_attr->priority = 0;
    flow_attr->num_of_specs = 3;
    flow_attr->port = 1;
    flow_attr->flags = 0;
    flow_attr->reserved = 0;
    buf += sizeof(struct ibv_exp_flow_attr);

    // Ethernet - filter auto-learning broadcast packets sent by switches
    auto *eth_spec = reinterpret_cast<struct ibv_exp_flow_spec_eth *>(buf);
    eth_spec->type = IBV_EXP_FLOW_SPEC_ETH;
    eth_spec->size = sizeof(struct ibv_exp_flow_spec_eth);
    memcpy(&eth_spec->val.dst_mac, resolve.mac_addr, sizeof(resolve.mac_addr));
    memset(&eth_spec->mask.dst_mac, 0xff, sizeof(resolve.mac_addr));
    buf += sizeof(struct ibv_exp_flow_spec_eth);

    // IPv4 - all wildcard
    auto *spec_ipv4 = reinterpret_cast<struct ibv_exp_flow_spec_ipv4_ext *>(buf);
    spec_ipv4->type = IBV_EXP_FLOW_SPEC_IPV4_EXT;
    spec_ipv4->size = sizeof(struct ibv_exp_flow_spec_ipv4_ext);
    buf += sizeof(struct ibv_exp_flow_spec_ipv4_ext);

    // UDP - steer packets for this UDP port
    auto *udp_spec = reinterpret_cast<struct ibv_exp_flow_spec_tcp_udp *>(buf);
    udp_spec->type = IBV_EXP_FLOW_SPEC_UDP;
    udp_spec->size = sizeof(struct ibv_exp_flow_spec_tcp_udp);
    udp_spec->val.dst_port = htons(rx_flow_udp_port);
    udp_spec->mask.dst_port = 0xffffu;

    recv_flow = ibv_exp_create_flow(qp_for_flow, flow_attr);
    rt_assert(recv_flow != nullptr, "Failed to create RECV flow");
}

void RawTransport::common_resolve_phy_port(uint8_t phy_port, size_t mtu)
{
    std::ostringstream xmsg; // The exception message
    int num_devices = 0;
    struct ibv_device **dev_list = ibv_get_device_list(&num_devices);
    rt_assert(dev_list != nullptr, "Failed to get device list");

    // Traverse the device list
    int ports_to_discover = phy_port;

    for (int dev_i = 0; dev_i < num_devices; dev_i++)
    {
        struct ibv_context *ib_ctx = ibv_open_device(dev_list[dev_i]);
        rt_assert(ib_ctx != nullptr, "Failed to open dev " + std::to_string(dev_i));

        struct ibv_device_attr device_attr;
        memset(&device_attr, 0, sizeof(device_attr));
        if (ibv_query_device(ib_ctx, &device_attr) != 0)
        {
            xmsg << "Failed to query device " << std::to_string(dev_i);
            throw std::runtime_error(xmsg.str());
        }

        for (uint8_t port_i = 1; port_i <= device_attr.phys_port_cnt; port_i++)
        {
            // Count this port only if it is enabled
            struct ibv_port_attr port_attr;
            if (ibv_query_port(ib_ctx, port_i, &port_attr) != 0)
            {
                xmsg << "Failed to query port " << std::to_string(port_i)
                     << " on device " << ib_ctx->device->name;
                throw std::runtime_error(xmsg.str());
            }

            if (port_attr.phys_state != IBV_PORT_ACTIVE &&
                port_attr.phys_state != IBV_PORT_ACTIVE_DEFER)
            {
                continue;
            }

            if (ports_to_discover == 0)
            {
                // Resolution succeeded. Check if the link layer matches.
                const auto expected_link_layer = IBV_LINK_LAYER_ETHERNET;
                if (port_attr.link_layer != expected_link_layer)
                {
                    throw std::runtime_error("Invalid link layer. Port link layer is " +
                                             link_layer_str(port_attr.link_layer));
                }

                // Check the MTU
                size_t active_mtu = enum_to_mtu(port_attr.active_mtu);
                if (mtu > active_mtu)
                {
                    throw std::runtime_error("Transport's required MTU is " +
                                             std::to_string(mtu) + ", active_mtu is " +
                                             std::to_string(active_mtu));
                }

                resolve.device_id = dev_i;
                resolve.ib_ctx = ib_ctx;
                resolve.dev_port_id = port_i;

                // Compute the bandwidth
                double gbps_per_lane = -1;
                switch (port_attr.active_speed)
                {
                case 1:
                    gbps_per_lane = 2.5;
                    break;
                case 2:
                    gbps_per_lane = 5.0;
                    break;
                case 4:
                    gbps_per_lane = 10.0;
                    break;
                case 8:
                    gbps_per_lane = 10.0;
                    break;
                case 16:
                    gbps_per_lane = 14.0;
                    break;
                case 32:
                    gbps_per_lane = 25.0;
                    break;
                default:
                    rt_assert(false, "Invalid active speed");
                };

                size_t num_lanes = SIZE_MAX;
                switch (port_attr.active_width)
                {
                case 1:
                    num_lanes = 1;
                    break;
                case 2:
                    num_lanes = 4;
                    break;
                case 4:
                    num_lanes = 8;
                    break;
                case 8:
                    num_lanes = 12;
                    break;
                default:
                    rt_assert(false, "Invalid active width");
                };

                double total_gbps = num_lanes * gbps_per_lane;
                resolve.bandwidth = total_gbps * (1000 * 1000 * 1000) / 8.0;

                fprintf(stderr,
                        "Port %u resolved to device %s, port %u. Speed = %.2f Gbps.\n",
                        phy_port, ib_ctx->device->name, port_i, total_gbps);

                resolve.ibdev_name = std::string(resolve.ib_ctx->device->name);
                resolve.netdev_name = ibdev2netdev(resolve.ibdev_name);
                resolve.ipv4_addr = get_interface_ipv4_addr(resolve.netdev_name);
                fill_interface_mac(resolve.netdev_name, resolve.mac_addr);

                return;
            }
            ports_to_discover--;
        }

        // Thank you Mario, but our port is in another device
        if (ibv_close_device(ib_ctx) != 0)
        {
            xmsg << "Failed to close device " << ib_ctx->device->name;
            throw std::runtime_error(xmsg.str());
        }
    }

    // If we are here, port resolution has failed
    assert(resolve.ib_ctx == nullptr);
    xmsg << "Failed to resolve verbs port index " << std::to_string(phy_port);
    throw std::runtime_error(xmsg.str());
}

void RawTransport::init_recvs()
{
    std::ostringstream xmsg; // The exception message

    // Initialize the memory region for RECVs
    buf = static_cast<uint8_t *>(mmap(NULL, kRingSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0));
    if (buf == MAP_FAILED)
    {
        xmsg << "Hugepage map failed ";
        throw std::runtime_error(xmsg.str());
    }
    memset(buf, 0, kRingSize);

    // Register the region
    recv_buf_mr = ibv_reg_mr(pd, buf, kRingSize, IBV_ACCESS_LOCAL_WRITE);
    // Fill in the Rpc's RX ring
    for (size_t i = 0; i < kNumRxRingEntries; i++)
    {
        rx_ring[i] = &buf[kRecvSize * i];
    }

    for (size_t i = 0; i < kRQDepth; i++)
    {
        recv_sgl[i].length = kRecvSize;
        recv_sgl[i].lkey = recv_buf_mr->lkey;
        recv_sgl[i].addr = reinterpret_cast<uint64_t>(&buf[i * kRecvSize]);

        recv_wr[i].wr_id = recv_sgl[i].addr; // For quick prefetch
        recv_wr[i].sg_list = &recv_sgl[i];
        recv_wr[i].num_sge = 1;

        // Circular link
        recv_wr[i].next = (i < kRQDepth - 1) ? &recv_wr[i + 1] : &recv_wr[0];
    }

    // Fill the RECV queue. post_recvs() can use fast RECV and therefore not
    // actually fill the RQ, so post_recvs() isn't usable here.
    struct ibv_recv_wr *bad_wr;
    recv_wr[kRQDepth - 1].next = nullptr;

    int ret = ibv_post_recv(qp, &recv_wr[0], &bad_wr);
    rt_assert(ret == 0, "Failed to fill RECV queue.");

    recv_wr[kRQDepth - 1].next = &recv_wr[0]; // Restore circularity
}

void RawTransport::init_sends(uint8_t *send_buf, size_t send_buf_size)
{
    send_buf_mr = ibv_reg_mr(pd, send_buf, send_buf_size, IBV_ACCESS_LOCAL_WRITE);
    for (size_t i = 0; i < kPostlist; i++)
    {
        send_wr[i].next = (i < kSQDepth - 1) ? &send_wr[i + 1] : &send_wr[0];
        send_wr[i].opcode = IBV_WR_SEND;
        send_wr[i].sg_list = &send_sgl[i][0];
        send_wr[i].num_sge = 1;
    }
}

void RawTransport::tx_one(uint64_t buf_addr, size_t pkt_size)
{
    struct ibv_send_wr &wr = send_wr[send_head];
    struct ibv_sge *sgl = send_sgl[send_head];

    assert(wr.opcode == IBV_WR_SEND);
    assert(wr.sg_list == send_sgl[send_head]);

    sgl[0].addr = buf_addr;
    sgl[0].length = pkt_size;
    sgl[0].lkey = send_buf_mr->lkey;

    wr.next = nullptr; // Break the chain

    wr.send_flags = IBV_SEND_SIGNALED;
    wr.num_sge = 1;

    struct ibv_send_wr *bad_wr;
    int ret = ibv_post_send(qp, &send_wr[send_head], &bad_wr);
    if (unlikely(ret != 0))
    {
        fprintf(stderr, "tx_flush post_send() failed. ret = %d\n", ret);
        assert(ret == 0);
        exit(-1);
    }

    poll_cq_one_helper(send_cq); // Poll the signaled WQE posted above
    wr.send_flags = 0;

    send_head = (send_head + 1) % kSQDepth;
}

void RawTransport::tx_burst(const std::vector<uint64_t> buf_addr, const std::vector<uint32_t> pkt_size, const size_t pkt_count)
{
    struct ibv_send_wr *first_wr, *last_wr, *temp_wr, *bad_wr;
    struct ibv_send_wr &wr = send_wr[send_head];

    assert(wr.opcode == IBV_WR_SEND);
    assert(wr.sg_list == send_sgl[send_head]);

    size_t first_wr_i = send_head;
    size_t last_wr_i = first_wr_i + (pkt_count - 1);
    if (last_wr_i >= kSQDepth)
        last_wr_i -= kSQDepth;

    first_wr = &send_wr[first_wr_i];
    last_wr = &send_wr[last_wr_i];
    temp_wr = last_wr->next;

    last_wr->next = nullptr;

    size_t sgl_i = first_wr_i;
    struct ibv_sge *sgl;

    for (size_t i = 0; i < pkt_count; i++)
    {
        assert(send_wr[sgl_i].opcode == IBV_WR_SEND);
        assert(send_wr[sgl_i].num_sge == 1);
        assert(send_wr[sgl_i].sg_list == send_sgl[sgl_i]);
        assert(send_wr[sgl_i].send_flags == 0);
        sgl = send_sgl[sgl_i];
        sgl[0].addr = buf_addr[i];
        sgl[0].length = pkt_size[i];
        sgl[0].lkey = send_buf_mr->lkey;
        sgl_i = (sgl_i + 1) % kSQDepth;
    }
    assert(sgl_i == (last_wr_i + 1) % kSQDepth);

    last_wr->send_flags = IBV_SEND_SIGNALED;

    int ret = ibv_post_send(qp, first_wr, &bad_wr);
    if (unlikely(ret != 0))
    {
        fprintf(stderr, "ibv_post_send() failed. ret = %d\n", ret);
        assert(ret == 0);
        exit(-1);
    }

    poll_cq_one_helper(send_cq); // Poll the signaled WQE posted above
    last_wr->send_flags = 0;
    last_wr->next = temp_wr; // Restore circularity
    send_head = last_wr_i;
    send_head = (send_head + 1) % kSQDepth;
}

size_t RawTransport::rx_burst()
{
    int ret = ibv_poll_cq(recv_cq, kPostlist, recv_wc);
    assert(ret >= 0);
    return static_cast<size_t>(ret);
}

void RawTransport::post_recvs(size_t num_recvs)
{
    assert(num_recvs <= kNumRxRingEntries); // num_recvs can be 0
    recvs_to_post += num_recvs;

    if (recvs_to_post < kRecvSlack)
        return;

    // The recvs posted are @first_wr through @last_wr, inclusive
    struct ibv_recv_wr *first_wr, *last_wr, *temp_wr, *bad_wr;

    size_t first_wr_i = recv_head;
    size_t last_wr_i = first_wr_i + (recvs_to_post - 1);
    if (last_wr_i >= kRQDepth)
        last_wr_i -= kRQDepth;

    first_wr = &recv_wr[first_wr_i];
    last_wr = &recv_wr[last_wr_i];
    temp_wr = last_wr->next;

    last_wr->next = nullptr;

    int ret = ibv_post_recv(qp, first_wr, &bad_wr);
    if (unlikely(ret != 0))
    {
        fprintf(stderr, "Redplane: Post RECV (normal) error %d\n", ret);
        exit(-1);
    }

    last_wr->next = temp_wr; // Restore circularity

    // Update RECV head: go to the last wr posted and take 1 more step
    recv_head = last_wr_i;
    recv_head = (recv_head + 1) % kRQDepth;
    recvs_to_post = 0; // Reset slack counter
    return;
}

void RawTransport::fill_local_routing_info(RoutingInfo *routing_info) const
{
    memset(static_cast<void *>(routing_info), 0, kMaxRoutingInfoSize);
    auto *ri = reinterpret_cast<eth_routing_info_t *>(routing_info);
    memcpy(ri->mac, resolve.mac_addr, 6);
    ri->ipv4_addr = resolve.ipv4_addr;
    ri->udp_port = rx_flow_udp_port;
}

} // namespace redplane