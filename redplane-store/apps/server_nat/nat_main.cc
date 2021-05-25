#include "nat_main.h"

void nat_handler(bool chain, std::string NextIpAddr, std::string TailIpAddr)
{
    std::random_device rd;     //Get a random seed from the OS entropy device, or whatever
    std::mt19937_64 eng(rd()); //Use the 64-bit Mersenne Twister 19937 generator
                             //and seed it with entropy.

    /******************************************************************** Chain replication *************************************************************************************/

    std::cout << chain << " " << NextIpAddr << " " << TailIpAddr << std::endl; 
    uint8_t *send_buf_chain = static_cast<uint8_t *>(mmap(NULL, redplane::RawTransport::kSendRingSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0));
    if (send_buf_chain == MAP_FAILED)
    {
        std::ostringstream xmsg; // The exception message
        xmsg << "Hugepage map failed ";
        throw std::runtime_error(xmsg.str());
    }
    memset(send_buf_chain, 0, redplane::RawTransport::kSendRingSize);
    redplane::RawTransport *raw_transport_chain = new redplane::RawTransport(kChainUDPPort, kPhyPorts, send_buf_chain, redplane::RawTransport::kSendRingSize);
    //uint8_t **rx_ring_chain = raw_transport_chain->getRxRing();
    
    redplane_req_pkt_t *redplane_req_pkt_buf = reinterpret_cast<redplane_req_pkt_t *>(send_buf_chain);
    // Get a routing info and fill in packet headers
    struct redplane::RawTransport::RoutingInfo local_ri_chain;
    raw_transport_chain->fill_local_routing_info(&local_ri_chain);
    auto *ri_chain = reinterpret_cast<redplane::eth_routing_info_t *>(&local_ri_chain);
    for (size_t i = 0; i < redplane::RawTransport::kSQDepth; i++)
    {  
        memcpy(redplane_req_pkt_buf[i].eth_hdr.src_mac, ri_chain->mac, 6);
        redplane_req_pkt_buf[i].eth_hdr.eth_type = htons(redplane::kIPEtherType);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.src_ip = htonl(ri_chain->ipv4_addr);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.version = 4;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.ihl = 5;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.ecn = 0;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.dscp = 0;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.id = htons(1);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.frag_off = htons(0);
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.tot_len = htons(sizeof(req_header_t));
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.ttl = 64;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.protocol = redplane::kIPHdrProtocol;
        redplane_req_pkt_buf[i].req_header.ipv4_hdr.check = 0;
        redplane_req_pkt_buf[i].req_header.udp_hdr.src_port = htons(kChainUDPPort); // UDP port of this thread
        redplane_req_pkt_buf[i].req_header.udp_hdr.dst_port = htons(kChainUDPPort);
        redplane_req_pkt_buf[i].req_header.udp_hdr.len = htons(sizeof(req_header_t)-sizeof(redplane::ipv4_hdr_t));
        redplane_req_pkt_buf[i].req_header.udp_hdr.check = 0;
    }
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    uint8_t *send_buf = static_cast<uint8_t *>(mmap(NULL, redplane::RawTransport::kSendRingSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0));
    if (send_buf == MAP_FAILED)
    {
        std::ostringstream xmsg; // The exception message
        xmsg << "Hugepage map failed ";
        throw std::runtime_error(xmsg.str());
    }
    memset(send_buf, 0, redplane::RawTransport::kSendRingSize);
    redplane::RawTransport *raw_transport = new redplane::RawTransport(0, kPhyPorts, send_buf, redplane::RawTransport::kSendRingSize);
    uint8_t **rx_ring = raw_transport->getRxRing();
    
    tcp_pkt_t *tcp_pkt_buf = reinterpret_cast<tcp_pkt_t *>(send_buf);
    // Get a routing info and fill in packet headers
    struct redplane::RawTransport::RoutingInfo local_ri;
    raw_transport->fill_local_routing_info(&local_ri);
    auto *ri = reinterpret_cast<redplane::eth_routing_info_t *>(&local_ri);
    for (size_t i = 0; i < redplane::RawTransport::kSQDepth; i++)
    {  
        memcpy(tcp_pkt_buf[i].eth_hdr.src_mac, ri->mac, 6);
        tcp_pkt_buf[i].eth_hdr.eth_type = htons(redplane::kIPEtherType);
        tcp_pkt_buf[i].ipv4_hdr.src_ip = htonl(ri->ipv4_addr);
        tcp_pkt_buf[i].ipv4_hdr.version = 4;
        tcp_pkt_buf[i].ipv4_hdr.ihl = 5;
        tcp_pkt_buf[i].ipv4_hdr.ecn = 0;
        tcp_pkt_buf[i].ipv4_hdr.dscp = 0;
        tcp_pkt_buf[i].ipv4_hdr.id = htons(1);
        tcp_pkt_buf[i].ipv4_hdr.frag_off = htons(0);
        tcp_pkt_buf[i].ipv4_hdr.ttl = 64;
        tcp_pkt_buf[i].ipv4_hdr.protocol = redplane::kIPHdrTCPProtocol;
        tcp_pkt_buf[i].tcp_hdr.check = 0;
    }

    std::vector<uint64_t> send_pkt_addr;
    std::vector<uint32_t> send_pkt_size;

    std::unordered_map<req_flow_key_t, req_value_t, hash_fn_t, equal_fn_t> nat_translation_map;
    std::uniform_int_distribution<uint32_t> distr;

    size_t num_pkts = 0;
    size_t last_rx_ring_idx = 0;
    size_t send_ring_idx = 0;
    size_t send_ring_chain_idx = 0;
    //FILE* flat = fopen("chain_latency.txt", "w");
    
    while (1) {
        num_pkts = raw_transport->rx_burst();
        for (size_t i = last_rx_ring_idx; i < last_rx_ring_idx + num_pkts; i++) {
            size_t idx = i % redplane::RawTransport::kNumRxRingEntries;
            tcp_pkt_t* req_pkt = reinterpret_cast<tcp_pkt_t *>(rx_ring[idx]);
            req_flow_key_t flow_key;
            req_value_t translated_value;
            flow_key.ip_addr = req_pkt->ipv4_hdr.src_ip;
            flow_key.port = req_pkt->tcp_hdr.src_port;

            if (nat_translation_map.find(flow_key) != nat_translation_map.end()) {
                //fprintf(stderr, "Existing key!\n");
                translated_value = nat_translation_map[flow_key];
                /******************************** Ask remote store ************************************/
                if (chain == true) {
                    memcpy(redplane_req_pkt_buf[send_ring_chain_idx].eth_hdr.dst_mac, req_pkt->eth_hdr.src_mac, 6);
                    redplane_req_pkt_buf[send_ring_chain_idx].req_header.flow_key.ip_addr = req_pkt->ipv4_hdr.src_ip;
                    redplane_req_pkt_buf[send_ring_chain_idx].req_header.flow_key.port = req_pkt->tcp_hdr.src_port;
                    redplane_req_pkt_buf[send_ring_chain_idx].req_header.ipv4_hdr.dst_ip = redplane::ipv4_from_str(TailIpAddr.c_str());
                    redplane_req_pkt_buf[send_ring_chain_idx].req_header.ipv4_hdr.check = 0;
                    redplane_req_pkt_buf[send_ring_chain_idx].req_header.ipv4_hdr.check = ip_checksum(&redplane_req_pkt_buf[send_ring_chain_idx].req_header.ipv4_hdr, sizeof(redplane::ipv4_hdr_t));

                    //fprintf(stderr, "Chain requested\n");
                    raw_transport_chain->tx_one(reinterpret_cast<uint64_t>(&(redplane_req_pkt_buf[send_ring_chain_idx])), sizeof(redplane::eth_hdr_t) + sizeof(req_header_t));
                    size_t num_pkts = 0;
                    while (1) {
                        num_pkts = raw_transport_chain->rx_burst();
                        if (num_pkts > 0) {
                            raw_transport_chain->post_recvs(num_pkts);
                            //fprintf(stderr, "Chain acked! %ld\n", num_pkts);
                            break;
                        }
                        if (unlikely(ctrl_c_pressed == 1))
                            break;
                    }
                    send_ring_chain_idx = (send_ring_chain_idx + 1) % redplane::RawTransport::kSQDepth;
                }
                /***************************************************************************************/
            } else {
                //fprintf(stderr, "New key!\n");
                translated_value.ip_addr = req_pkt->ipv4_hdr.src_ip;
                translated_value.port = req_pkt->tcp_hdr.src_port;
                nat_translation_map[flow_key] = translated_value;
                /******************************** Ask remote store ************************************/
                if (chain == true) {
                    memcpy(redplane_req_pkt_buf[send_ring_chain_idx].eth_hdr.dst_mac, req_pkt->eth_hdr.src_mac, 6);
                    redplane_req_pkt_buf[send_ring_chain_idx].req_header.flow_key.ip_addr = req_pkt->ipv4_hdr.src_ip;
                    redplane_req_pkt_buf[send_ring_chain_idx].req_header.flow_key.port = req_pkt->tcp_hdr.src_port;
                    redplane_req_pkt_buf[send_ring_chain_idx].req_header.ipv4_hdr.dst_ip = redplane::ipv4_from_str(NextIpAddr.c_str());
                    redplane_req_pkt_buf[send_ring_chain_idx].req_header.ipv4_hdr.check = 0;
                    redplane_req_pkt_buf[send_ring_chain_idx].req_header.ipv4_hdr.check = ip_checksum(&redplane_req_pkt_buf[send_ring_chain_idx].req_header.ipv4_hdr, sizeof(redplane::ipv4_hdr_t));

                    //fprintf(stderr, "Chain requested\n");
                    //auto start = std::chrono::high_resolution_clock::now();
                    raw_transport_chain->tx_one(reinterpret_cast<uint64_t>(&(redplane_req_pkt_buf[send_ring_chain_idx])), sizeof(redplane::eth_hdr_t) + sizeof(req_header_t));
                    size_t num_pkts = 0;
                    while (1) {
                        num_pkts = raw_transport_chain->rx_burst();
                        if (num_pkts > 0) {
                            //auto stop = std::chrono::high_resolution_clock::now();
                            //auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
                            //uint32_t latency_us = (static_cast<uint32_t>(duration.count()));
                            //fprintf(flat, "%d\n", latency_us);
                            raw_transport_chain->post_recvs(num_pkts);
                            //fprintf(stderr, "Chain acked! %ld\n", num_pkts);
                            break;
                        }
                        if (unlikely(ctrl_c_pressed == 1))
                            break;
                    }
                    send_ring_chain_idx = (send_ring_chain_idx + 1) % redplane::RawTransport::kSQDepth;
                }
                /***************************************************************************************/
            }
            memcpy(tcp_pkt_buf[i].eth_hdr.dst_mac, req_pkt->eth_hdr.src_mac, 6);
            tcp_pkt_buf[send_ring_idx].ipv4_hdr.check = 0;
            tcp_pkt_buf[send_ring_idx].ipv4_hdr.src_ip = req_pkt->ipv4_hdr.dst_ip; 
            tcp_pkt_buf[send_ring_idx].ipv4_hdr.dst_ip = translated_value.ip_addr;
            tcp_pkt_buf[send_ring_idx].tcp_hdr.src_port = distr(eng) % 65536;
            tcp_pkt_buf[send_ring_idx].tcp_hdr.dst_port = translated_value.port;
            tcp_pkt_buf[send_ring_idx].ipv4_hdr.tot_len = req_pkt->ipv4_hdr.tot_len;
            tcp_pkt_buf[send_ring_idx].ipv4_hdr.check = ip_checksum(&tcp_pkt_buf[send_ring_idx].ipv4_hdr, sizeof(redplane::ipv4_hdr_t));
            
            send_pkt_addr.push_back(reinterpret_cast<uint64_t>(&(tcp_pkt_buf[send_ring_idx])));
            send_pkt_size.push_back(sizeof(redplane::eth_hdr_t) + ntohs(tcp_pkt_buf[send_ring_idx].ipv4_hdr.tot_len));
            //fprintf(stderr, "packet len: %d\n", ntohs(tcp_pkt_buf[send_ring_idx].ipv4_hdr.tot_len));
            send_ring_idx = (send_ring_idx + 1) % redplane::RawTransport::kSQDepth;
        }
        if (num_pkts > 0) {
            last_rx_ring_idx = (last_rx_ring_idx + num_pkts) % redplane::RawTransport::kNumRxRingEntries;
            raw_transport->tx_burst(send_pkt_addr, send_pkt_size, send_pkt_addr.size());
            raw_transport->post_recvs(num_pkts);
            send_pkt_addr.clear();
            send_pkt_size.clear();
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
        req_handler_thread[i] = std::thread(nat_handler, FLAGS_chain, FLAGS_nextip, FLAGS_tailip);
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