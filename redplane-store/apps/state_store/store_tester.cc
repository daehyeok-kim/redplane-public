#include "store_tester.h"

void req_handler(uint16_t dest_port_num, size_t payload_size)
{
    std::srand(std::time(nullptr));
    uint8_t *send_buf = static_cast<uint8_t *>(mmap(NULL, redplane::RawTransport::kSendRingSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0));
    if (send_buf == MAP_FAILED)
    {
        std::ostringstream xmsg; // The exception message
        xmsg << "Hugepage map failed ";
        throw std::runtime_error(xmsg.str());
    }
    memset(send_buf, 0, redplane::RawTransport::kSendRingSize);
    redplane::RawTransport *raw_transport = new redplane::RawTransport(dest_port_num, kPhyPorts, send_buf, redplane::RawTransport::kSendRingSize);
    //uint8_t **rx_ring = raw_transport->getRxRing();
    redplane_req_pkt_t *redplane_req_pkt_buf = reinterpret_cast<redplane_req_pkt_t *>(send_buf);
    // Get a routing info and fill in packet headers
    struct redplane::RawTransport::RoutingInfo local_ri;
    raw_transport->fill_local_routing_info(&local_ri);

    //uint32_t flow_key = static_cast<uint32_t>(std::rand());
    uint32_t flow_key = static_cast<uint32_t>(dest_port_num);
    uint32_t value = static_cast<uint32_t>(std::rand());

    // Prepare a template of ack packets
    for (size_t i = 0; i < redplane::RawTransport::kSQDepth; i++)
    {
        auto *ri = reinterpret_cast<redplane::eth_routing_info_t *>(&local_ri);
        memcpy(redplane_req_pkt_buf[i].eth_hdr.src_mac, ri->mac, 6);
        memcpy(redplane_req_pkt_buf[i].eth_hdr.dst_mac, kDestMacAddr, 6);
        redplane_req_pkt_buf[i].eth_hdr.eth_type = htons(redplane::kIPEtherType);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.src_ip = htonl(ri->ipv4_addr);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.dst_ip = redplane::ipv4_from_str(kReceiverIpAddr.c_str());
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.version = 4;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.ihl = 5;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.ecn = 0;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.dscp = 0;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.id = htons(1);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.frag_off = htons(0);
        //redplane_req_pkt_buf[i].req_header.ipv4_hdr.tot_len = htons(sizeof(req_header_t) + sizeof(redplane::ipv4_hdr_t) + payload_size);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.tot_len = htons(sizeof(req_header_t) + payload_size);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.ttl = 64;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.protocol = redplane::kIPHdrProtocol;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.check = ip_checksum(&redplane_req_pkt_buf[i].req_header.ipv4_hdr, sizeof(redplane::ipv4_hdr_t));
        redplane_req_pkt_buf[i].req_header.udp_hdr.src_port = htons(dest_port_num); // Common UDP port of switch
        redplane_req_pkt_buf[i].req_header.udp_hdr.dst_port = htons(dest_port_num); // UDP port of this thread
        //redplane_req_pkt_buf[i].req_header.udp_hdr.len = htons(sizeof(req_header_t) - sizeof(redplane::ipv4_hdr_t) + payload_size);
        redplane_req_pkt_buf[i].req_header.udp_hdr.len = htons(sizeof(req_header_t) - sizeof(redplane::ipv4_hdr_t) + payload_size);
        redplane_req_pkt_buf[i].req_header.udp_hdr.check = 0;
        redplane_req_pkt_buf[i].req_header.flow_key.ip_addr = flow_key;
        redplane_req_pkt_buf[i].req_header.value.ip_addr = value;
    }

    std::vector<uint64_t> send_pkt_addr;
    std::vector<uint32_t> send_pkt_size;
    //redplane_req_pkt_buf[0].req_header.req_type = req_type_t::LEASE_NEW_REQ;
    //redplane_req_pkt_buf[0].req_header.seq_num = 0;
    //raw_transport->tx_one(reinterpret_cast<uint64_t>(&redplane_req_pkt_buf[0]), sizeof(redplane::eth_hdr_t) + sizeof(req_header_t) + sizeof(redplane::ipv4_hdr_t) + payload_size);

    while (true)
    {   
        size_t num_pkts = raw_transport->rx_burst();
        for (size_t i = 0; i < redplane::RawTransport::kSQDepth; i++)
        {
            if (i == 0)
            {
                redplane_req_pkt_buf[i].req_header.req_type = req_type_t::LEASE_NEW_REQ;
            }
            else
            {
                redplane_req_pkt_buf[i].req_header.req_type = req_type_t::LEASE_RENEW_REQ;
            }
            redplane_req_pkt_buf[i].req_header.seq_num = i % MAX_SEQ;
            send_pkt_addr.push_back(reinterpret_cast<uint64_t>(&redplane_req_pkt_buf[i]));
            //send_pkt_size.push_back(sizeof(redplane::eth_hdr_t) + sizeof(req_header_t) + sizeof(redplane::ipv4_hdr_t) + payload_size);
            send_pkt_size.push_back(sizeof(redplane::eth_hdr_t) + sizeof(req_header_t) + payload_size);
        }
        raw_transport->tx_burst(send_pkt_addr, send_pkt_size, send_pkt_size.size());
        send_pkt_addr.clear();
        send_pkt_size.clear();

        raw_transport->post_recvs(num_pkts);

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
        req_handler_thread[i] = std::thread(req_handler, kUDPPort + i + 1, FLAGS_payload_size);
        bind_to_core(req_handler_thread[i], 0, i+1);
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