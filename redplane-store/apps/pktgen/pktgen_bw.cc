#include "pktgen.h"

void pktgen_handler(std::string DestIpAddr)
{
    std::random_device rd;     //Get a random seed from the OS entropy device, or whatever
    std::mt19937_64 eng(rd()); //Use the 64-bit Mersenne Twister 19937 generator
                             //and seed it with entropy.

    uint8_t *send_buf = static_cast<uint8_t *>(mmap(NULL, redplane::RawTransport::kSendRingSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0));
    if (send_buf == MAP_FAILED)
    {
        std::ostringstream xmsg; // The exception message
        xmsg << "Hugepage map failed ";
        throw std::runtime_error(xmsg.str());
    }
    memset(send_buf, 0, redplane::RawTransport::kSendRingSize);
    redplane::RawTransport *raw_transport = new redplane::RawTransport(0, kPhyPorts, send_buf, redplane::RawTransport::kSendRingSize);
    //uint8_t **rx_ring = raw_transport->getRxRing();
    
    std::vector<uint64_t> send_pkt_addr;
    std::vector<uint32_t> send_pkt_size;
    tcp_pkt_t *tcp_pkt_buf = reinterpret_cast<tcp_pkt_t *>(send_buf);
    // Get a routing info and fill in packet headers
    struct redplane::RawTransport::RoutingInfo local_ri;
    raw_transport->fill_local_routing_info(&local_ri);
    auto *ri = reinterpret_cast<redplane::eth_routing_info_t *>(&local_ri);
    for (size_t i = 0; i < redplane::RawTransport::kSQDepth; i++)
    {  
        memcpy(tcp_pkt_buf[i].eth_hdr.src_mac, ri->mac, 6);
        memcpy(tcp_pkt_buf[i].eth_hdr.dst_mac, kDestMacAddr, 6);
        tcp_pkt_buf[i].eth_hdr.eth_type = htons(redplane::kIPEtherType);
        tcp_pkt_buf[i].ipv4_hdr.src_ip = htonl(ri->ipv4_addr);
        tcp_pkt_buf[i].ipv4_hdr.dst_ip =  redplane::ipv4_from_str(DestIpAddr.c_str());
        tcp_pkt_buf[i].ipv4_hdr.version = 4;
        tcp_pkt_buf[i].ipv4_hdr.ihl = 5;
        tcp_pkt_buf[i].ipv4_hdr.ecn = 0;
        tcp_pkt_buf[i].ipv4_hdr.dscp = 0;
        tcp_pkt_buf[i].ipv4_hdr.id = htons(1);
        tcp_pkt_buf[i].ipv4_hdr.frag_off = htons(0);
        tcp_pkt_buf[i].ipv4_hdr.ttl = 64;
        tcp_pkt_buf[i].ipv4_hdr.protocol = redplane::kIPHdrTCPProtocol;
        tcp_pkt_buf[i].ipv4_hdr.check = 0;
        tcp_pkt_buf[i].ipv4_hdr.tot_len = htons(64);
        tcp_pkt_buf[i].ipv4_hdr.check = ip_checksum(&tcp_pkt_buf[i].ipv4_hdr, sizeof(redplane::ipv4_hdr_t));
        tcp_pkt_buf[i].tcp_hdr.src_port = htons(1234); // UDP port of this thread
        tcp_pkt_buf[i].tcp_hdr.dst_port = htons(5678);
        tcp_pkt_buf[i].tcp_hdr.check = 0;
        send_pkt_addr.push_back(reinterpret_cast<uint64_t>(&(tcp_pkt_buf[i])));
        send_pkt_size.push_back(sizeof(redplane::eth_hdr_t) + 64);
    }

    while (true) 
    {
        raw_transport->tx_burst(send_pkt_addr, send_pkt_size, send_pkt_size.size());

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
        //req_handler_thread[i] = std::thread(req_handler, kUDPPort + i + 1, FLAGS_m_lat);
        req_handler_thread[i] = std::thread(pktgen_handler, FLAGS_destip);
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