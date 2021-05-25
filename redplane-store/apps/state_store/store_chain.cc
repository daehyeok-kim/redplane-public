#include "store_chain.h"

void req_handler(uint16_t port_num, std::string NextIpAddr)
{
    // Key-value store
    std::unordered_map<req_flow_key_t, req_value_t, hash_fn_t, equal_fn_t> state_store;
    
    /********************************************* Setup chain replication *****************************************************/ 
    uint8_t *send_buf = static_cast<uint8_t *>(mmap(NULL, redplane::RawTransport::kSendRingSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0));
    if (send_buf == MAP_FAILED)
    {
        std::ostringstream xmsg; // The exception message
        xmsg << "Hugepage map failed ";
        throw std::runtime_error(xmsg.str());
    }
    memset(send_buf, 0, redplane::RawTransport::kSendRingSize);
    redplane::RawTransport *raw_transport = new redplane::RawTransport(port_num, kPhyPorts, send_buf, redplane::RawTransport::kSendRingSize);
    uint8_t **rx_ring_chain = raw_transport->getRxRing();
    redplane_req_pkt_t *redplane_req_pkt_buf = reinterpret_cast<redplane_req_pkt_t *>(send_buf);
    // Get a routing info and fill in packet headers
    struct redplane::RawTransport::RoutingInfo local_ri_chain;
    raw_transport->fill_local_routing_info(&local_ri_chain);
    auto *ri = reinterpret_cast<redplane::eth_routing_info_t *>(&local_ri_chain);
    // Prepare a template of ack packets
    for (size_t i = 0; i < redplane::RawTransport::kSQDepth; i++)
    {
        memcpy(redplane_req_pkt_buf[i].eth_hdr.src_mac, ri->mac, 6);
        redplane_req_pkt_buf[i].eth_hdr.eth_type = htons(redplane::kIPEtherType);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.src_ip = htonl(ri->ipv4_addr);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.dst_ip = redplane::ipv4_from_str(NextIpAddr.c_str());
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.version = 4;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.ihl = 5;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.ecn = 0;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.dscp = 0;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.id = htons(1);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.frag_off = htons(0);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.tot_len = htons(sizeof(req_header_t));
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.ttl = 64;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.protocol = redplane::kIPHdrProtocol;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.check = ip_checksum(&redplane_req_pkt_buf[i].req_header.ipv4_hdr, sizeof(redplane::ipv4_hdr_t));
        redplane_req_pkt_buf[i].req_header.udp_hdr.src_port = htons(port_num); // UDP port of this thread
        redplane_req_pkt_buf[i].req_header.udp_hdr.dst_port = htons(port_num);
        redplane_req_pkt_buf[i].req_header.udp_hdr.check = 0;
    }
    /*************************************************************************************************************************/
    
    redplane_req_pkt_t *req_pkt;
    size_t send_ring_idx = 0;
    size_t last_rx_ring_idx = 0;
    std::vector<uint64_t> send_pkt_addr;
    std::vector<uint32_t> send_pkt_size;
    while (true)
    {
        size_t num_pkts = raw_transport->rx_burst();
        fprintf(stderr, "Chain received! %ld\n", num_pkts);
        if (num_pkts > 0)
        {
            for (size_t i = last_rx_ring_idx; i < last_rx_ring_idx + num_pkts; i++)
            {
                size_t idx = i % redplane::RawTransport::kNumRxRingEntries;
                req_pkt = reinterpret_cast<redplane_req_pkt_t *>(rx_ring_chain[idx]);
                redplane_req_pkt_buf[send_ring_idx].req_header.seq_num = req_pkt->req_header.seq_num;
                memcpy(&(redplane_req_pkt_buf[send_ring_idx].req_header.flow_key), &(req_pkt->req_header.flow_key), sizeof(req_flow_key_t));
                memcpy(&(redplane_req_pkt_buf[send_ring_idx].req_header.value), &(req_pkt->req_header.value), sizeof(req_value_t));
                memcpy(redplane_req_pkt_buf[send_ring_idx].eth_hdr.dst_mac, req_pkt->eth_hdr.src_mac, 6);
                send_pkt_addr.push_back(reinterpret_cast<uint64_t>(&(redplane_req_pkt_buf[send_ring_idx])));
                send_pkt_size.push_back(sizeof(redplane::eth_hdr_t) + sizeof(req_header_t));
                send_ring_idx = (send_ring_idx + 1) % redplane::RawTransport::kSQDepth;
            }
            raw_transport->tx_burst(send_pkt_addr, send_pkt_size, send_pkt_size.size());
            raw_transport->post_recvs(num_pkts);
            send_pkt_size.clear();
            send_pkt_addr.clear();
            last_rx_ring_idx = (last_rx_ring_idx + num_pkts) % redplane::RawTransport::kNumRxRingEntries;
        }

        if (unlikely(ctrl_c_pressed == 1))
            break;
    }
    munmap(send_buf, redplane::RawTransport::kSendRingSize);
}

int main(int argc, char **argv)
{
    signal(SIGINT, ctrl_c_handler);
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    assert(FLAGS_threads <= kNumThreads);

    std::thread req_handler_thread[kNumThreads];

    for (size_t i = 0; i < FLAGS_threads; i++)
    {
        req_handler_thread[i] = std::thread(req_handler, kUDPPort + i + 1, FLAGS_nextip);
        bind_to_core(req_handler_thread[i], 0, i);
    }

    while (1)
    {
        std::chrono::milliseconds dura(2000);
        std::this_thread::sleep_for(dura);
        if (unlikely(ctrl_c_pressed == 1))
            break;
    }

    for (size_t i = 0; i < FLAGS_threads; i++)
    {
        req_handler_thread[i].join();
    }

    return 0;
}