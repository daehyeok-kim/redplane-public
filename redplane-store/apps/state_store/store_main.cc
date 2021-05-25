#include "store_main.h"

void req_handler(uint16_t port_num, bool m_lat, bool chain, std::string NextIpAddr)
{
    // Key-value store
    std::unordered_map<req_flow_key_t, req_value_t, hash_fn_t, equal_fn_t> state_store;
    std::unordered_map<req_flow_key_t, uint16_t, hash_fn_t, equal_fn_t> last_seq_num;
    std::unordered_map<req_flow_key_t, uint32_t, hash_fn_t, equal_fn_t> lease;
    
    /********************************************* Setup chain replication *****************************************************/ 
    uint8_t *send_buf_chain = static_cast<uint8_t *>(mmap(NULL, redplane::RawTransport::kSendRingSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0));
    if (send_buf_chain == MAP_FAILED)
    {
        std::ostringstream xmsg; // The exception message
        xmsg << "Hugepage map failed ";
        throw std::runtime_error(xmsg.str());
    }
    memset(send_buf_chain, 0, redplane::RawTransport::kSendRingSize);
    redplane::RawTransport *raw_transport_chain = new redplane::RawTransport(port_num+1000, kPhyPorts, send_buf_chain, redplane::RawTransport::kSendRingSize);
    //uint8_t **rx_ring_chain = raw_transport_chain->getRxRing();
    redplane_req_pkt_t *redplane_req_pkt_buf = reinterpret_cast<redplane_req_pkt_t *>(send_buf_chain);
    // Get a routing info and fill in packet headers
    struct redplane::RawTransport::RoutingInfo local_ri_chain;
    raw_transport_chain->fill_local_routing_info(&local_ri_chain);
    // Prepare a template of ack packets
    for (size_t i = 0; i < redplane::RawTransport::kSQDepth; i++)
    {
        auto *ri = reinterpret_cast<redplane::eth_routing_info_t *>(&local_ri_chain);
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
        redplane_req_pkt_buf[i].req_header.udp_hdr.src_port = htons(port_num+1000); // UDP port of this thread
        redplane_req_pkt_buf[i].req_header.udp_hdr.dst_port = htons(port_num+1000);
        redplane_req_pkt_buf[i].req_header.udp_hdr.check = 0;
    }
    /*************************************************************************************************************************/
    
    uint8_t *send_buf = static_cast<uint8_t *>(mmap(NULL, redplane::RawTransport::kSendRingSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0));
    if (send_buf == MAP_FAILED)
    {
        std::ostringstream xmsg; // The exception message
        xmsg << "Hugepage map failed ";
        throw std::runtime_error(xmsg.str());
    }
    memset(send_buf, 0, redplane::RawTransport::kSendRingSize);
    redplane::RawTransport *raw_transport = new redplane::RawTransport(port_num, kPhyPorts, send_buf, redplane::RawTransport::kSendRingSize);
    uint8_t **rx_ring = raw_transport->getRxRing();
    redplane_ack_pkt_t *redplane_ack_pkt_buf = reinterpret_cast<redplane_ack_pkt_t *>(send_buf);
    // Get a routing info and fill in packet headers
    struct redplane::RawTransport::RoutingInfo local_ri;
    raw_transport->fill_local_routing_info(&local_ri);

    // Prepare a template of ack packets
    for (size_t i = 0; i < redplane::RawTransport::kSQDepth; i++)
    {
        auto *ri = reinterpret_cast<redplane::eth_routing_info_t *>(&local_ri);
        memcpy(redplane_ack_pkt_buf[i].eth_hdr.src_mac, ri->mac, 6);
        redplane_ack_pkt_buf[i].eth_hdr.eth_type = htons(redplane::kIPEtherType);
        redplane_ack_pkt_buf[i].ack_header.ipv4_hdr.src_ip = htonl(ri->ipv4_addr);
        redplane_ack_pkt_buf[i].ack_header.ipv4_hdr.version = 4;
        redplane_ack_pkt_buf[i].ack_header.ipv4_hdr.ihl = 5;
        redplane_ack_pkt_buf[i].ack_header.ipv4_hdr.ecn = 0;
        redplane_ack_pkt_buf[i].ack_header.ipv4_hdr.dscp = 0;
        redplane_ack_pkt_buf[i].ack_header.ipv4_hdr.id = htons(1);
        redplane_ack_pkt_buf[i].ack_header.ipv4_hdr.frag_off = htons(0);
        redplane_ack_pkt_buf[i].ack_header.ipv4_hdr.ttl = 64;
        redplane_ack_pkt_buf[i].ack_header.ipv4_hdr.protocol = redplane::kIPHdrProtocol;
        redplane_ack_pkt_buf[i].ack_header.udp_hdr.src_port = htons(port_num); // UDP port of this thread
        redplane_ack_pkt_buf[i].ack_header.udp_hdr.dst_port = htons(kSwitchUDPPort);
        redplane_ack_pkt_buf[i].ack_header.udp_hdr.check = 0;
    }

    size_t total_recvd = 0;
    size_t last_rx_ring_idx = 0;
    redplane_req_pkt_t *req_pkt;
    redplane_req_pkt_t *chain_req_pkt;

    auto start = std::chrono::high_resolution_clock::now();
    auto stop = std::chrono::high_resolution_clock::now();
    auto per_packet_start = std::chrono::high_resolution_clock::now();
    auto per_packet_stop = std::chrono::high_resolution_clock::now();
    std::vector<uint64_t> send_pkt_addr;
    std::vector<uint32_t> send_pkt_size;

    // Per-* latency statistics
    std::vector<uint64_t> per_write_latency;
    std::vector<uint64_t> per_read_latency;
    std::vector<uint64_t> per_new_latency;
    std::vector<uint64_t> per_migrate_latency;

    // Touch data structures to warm up
    //state_store.insert(std::make_pair<req_flow_key_t, req_value_t>({0, 0}, {0, 0}));
    //last_seq_num.insert(std::make_pair<req_flow_key_t, uint16_t>({0, 0}, 0));
    //lease.insert(std::make_pair<req_flow_key_t, uint32_t>({0, 0}, 0));
    // sequencer 
    state_store.insert(std::make_pair<req_flow_key_t, req_value_t>({0}, {0}));
    last_seq_num.insert(std::make_pair<req_flow_key_t, uint16_t>({0}, 0));
    lease.insert(std::make_pair<req_flow_key_t, uint32_t>({0}, 0));

    size_t send_ring_idx = 0;
    size_t chain_send_ring_idx = 0;
    uint16_t request_size = 0;
    while (true)
    {
        chain_req_pkt = nullptr;
        size_t num_pkts = raw_transport->rx_burst();
        if (num_pkts > 0)
        {
            //fprintf(stderr, "%ld packets received.\n", num_pkts);
            if (total_recvd == 0)
            {
                start = std::chrono::high_resolution_clock::now();
            }
            //auto lease_expire_time = std::chrono::system_clock::now() + std::chrono::seconds(kLeasePeriod);
            for (size_t i = last_rx_ring_idx; i < last_rx_ring_idx + num_pkts; i++)
            {
                if (m_lat)
                {
                    per_packet_start = std::chrono::high_resolution_clock::now();
                }
                size_t idx = i % redplane::RawTransport::kNumRxRingEntries;
                req_pkt = reinterpret_cast<redplane_req_pkt_t *>(rx_ring[idx]);
                req_flow_key_t flow_key = req_pkt->req_header.flow_key;
                uint16_t original_pkt_len = ntohs(req_pkt->original_ipv4_hdr.tot_len);
                request_size = ntohs(req_pkt->req_header.ipv4_hdr.tot_len);
                uint16_t seq_num = ntohs(req_pkt->req_header.seq_num);
                redplane_ack_pkt_buf[send_ring_idx].ack_header.ipv4_hdr.check = 0;
                send_pkt_addr.push_back(reinterpret_cast<uint64_t>(&(redplane_ack_pkt_buf[send_ring_idx])));

                switch (req_pkt->req_header.req_type)
                {
                // new: depending on the kv store, choose renew or migrate_ack
                case req_type_t::LEASE_NEW_REQ:
                    // If there is no lease or it has been expired
                    if (lease.find(flow_key) == lease.end())
                    {
                        //fprintf(stderr, "Prepare LEASE_NEW_ACK\n");
                        // It is a really new flow, so create a slot for it.
                         
                        //state_store.insert(std::make_pair(flow_key, req_value_t{0, 0}));
                        
                        //sequencer 
                        state_store.insert(std::make_pair(flow_key, req_value_t{0}));
                        last_seq_num.insert(std::make_pair(flow_key, 0));
                        redplane_ack_pkt_buf[send_ring_idx].ack_header.ack_type = ack_type_t::LEASE_NEW_ACK;
                        redplane_ack_pkt_buf[send_ring_idx].ack_header.ipv4_hdr.tot_len = htons(sizeof(ack_header_t) + original_pkt_len);
                        redplane_ack_pkt_buf[send_ring_idx].ack_header.udp_hdr.len = htons(sizeof(ack_header_t) - sizeof(redplane::ipv4_hdr_t) + original_pkt_len);
                        redplane_ack_pkt_buf[send_ring_idx].ack_header.seq_num = 0;

                        // Copying the original IP payload
                        memcpy(reinterpret_cast<uint8_t *>(&(redplane_ack_pkt_buf[send_ring_idx])) + sizeof(redplane::eth_hdr_t) + sizeof(ack_header_t), &(req_pkt->original_ipv4_hdr), original_pkt_len);
                        send_pkt_size.push_back(sizeof(redplane::eth_hdr_t) + sizeof(ack_header_t) + original_pkt_len);
                    }
                    // If there exists a lease
                    else
                    {
                        //fprintf(stderr, "Prepare LEASE_MIGRATE_ACK\n");
                        redplane_ack_pkt_buf[send_ring_idx].ack_header.ack_type = ack_type_t::LEASE_MIGRATE_ACK;
                        // Copying the state to the ack packet
                        memcpy(reinterpret_cast<uint8_t *>(&(redplane_ack_pkt_buf[send_ring_idx])) + sizeof(redplane::eth_hdr_t) + sizeof(ack_header_t), &state_store[flow_key], sizeof(req_value_t));
                        // Copying the original IP payload
                        memcpy(reinterpret_cast<uint8_t *>(&(redplane_ack_pkt_buf[send_ring_idx])) + sizeof(redplane::eth_hdr_t) + sizeof(ack_header_t) + sizeof(req_value_t), &(req_pkt->original_ipv4_hdr), original_pkt_len);
                        send_pkt_size.push_back(sizeof(redplane::eth_hdr_t) + sizeof(ack_header_t) + sizeof(req_value_t) + original_pkt_len);
                        redplane_ack_pkt_buf[send_ring_idx].ack_header.ipv4_hdr.tot_len = htons(sizeof(ack_header_t) + sizeof(req_value_t) + original_pkt_len);
                        redplane_ack_pkt_buf[send_ring_idx].ack_header.udp_hdr.len = htons(sizeof(ack_header_t) - sizeof(redplane::ipv4_hdr_t) + sizeof(req_value_t) + original_pkt_len);
                    }
                    break;
                case req_type_t::LEASE_RENEW_REQ:
                    //fprintf(stderr, "Prepare LEASE_RENEW_ACK %d\n", ntohs(req_pkt->req_header.ipv4_hdr.tot_len));
                    // The requested flow key must exist!
                    if (lease.find(flow_key) == lease.end())
                    {
                        //state_store.insert(std::make_pair(flow_key, req_value_t{0, 0}));
                        // Seuquencer
                        state_store.insert(std::make_pair(flow_key, req_value_t{0}));
                        last_seq_num.insert(std::make_pair(flow_key, 0));
                    }
                    assert(last_seq_num.find(flow_key) != last_seq_num.end());
                    redplane_ack_pkt_buf[send_ring_idx].ack_header.ack_type = ack_type_t::LEASE_RENEW_ACK;
                    redplane_ack_pkt_buf[send_ring_idx].ack_header.seq_num = htons(seq_num);
                    redplane_ack_pkt_buf[send_ring_idx].ack_header.ipv4_hdr.tot_len = htons(sizeof(ack_header_t) + original_pkt_len);
                    redplane_ack_pkt_buf[send_ring_idx].ack_header.udp_hdr.len = htons(sizeof(ack_header_t) - sizeof(redplane::ipv4_hdr_t) + original_pkt_len);

                    // Write transaction
                    if (seq_num != 0)
                    {
                        // Copying the original packet to the packet
                        memcpy(reinterpret_cast<uint8_t *>(&(redplane_ack_pkt_buf[send_ring_idx])) + sizeof(redplane::eth_hdr_t) + sizeof(ack_header_t), &(req_pkt->original_ipv4_hdr), original_pkt_len);
                        send_pkt_size.push_back(sizeof(redplane::eth_hdr_t) + sizeof(ack_header_t) + original_pkt_len);

                        // Commit state only if the request sequence number is greater than the last seen sequence number
                        if (last_seq_num[flow_key] < seq_num)
                        {
                            memcpy(&state_store[flow_key], &(req_pkt->req_header.value), sizeof(req_value_t));
                            last_seq_num[flow_key] = seq_num;

                            //Update the pointer for chain replication
                            chain_req_pkt = req_pkt;
                        }
                    }
                    else
                    {
                        //fprintf(stderr, "Read-only\n");
                        // Read-only transaction
                        send_pkt_size.push_back(sizeof(redplane::eth_hdr_t) + sizeof(ack_header_t));
                    }
                    break;
                }
                // Update Dst MAC and IP addr
                memcpy(redplane_ack_pkt_buf[send_ring_idx].eth_hdr.dst_mac, &req_pkt->eth_hdr.src_mac, 6);
                redplane_ack_pkt_buf[send_ring_idx].ack_header.ipv4_hdr.dst_ip = redplane::ipv4_from_str(NextIpAddr.c_str()); // FIXME!!
                //redplane_ack_pkt_buf[send_ring_idx].ack_header.ipv4_hdr.dst_ip = req_pkt->req_header.ipv4_hdr.src_ip;

                lease.insert(std::make_pair(flow_key, 0));
                //std::chrono::duration_cast<std::chrono::milliseconds>(lease_expire_time.time_since_epoch()).count()));

                // Copy the flow key to the ack
                memcpy(&(redplane_ack_pkt_buf[send_ring_idx].ack_header.flow_key), &flow_key, sizeof(req_flow_key_t));

                // Calculate IPv4 checksum
                redplane_ack_pkt_buf[send_ring_idx].ack_header.ipv4_hdr.check = ip_checksum(&redplane_ack_pkt_buf[send_ring_idx].ack_header.ipv4_hdr, sizeof(redplane::ipv4_hdr_t));
                //print_bytes(reinterpret_cast<uint8_t*>(&redplane_ack_pkt_buf[send_ring_idx]));

                if (m_lat)
                {
                    // Record per-* latency statistics
                    per_packet_stop = std::chrono::high_resolution_clock::now();
                    auto per_packet_dur = std::chrono::duration_cast<std::chrono::nanoseconds>(per_packet_stop - per_packet_start);
                    switch (req_pkt->req_header.req_type)
                    {
                    case req_type_t::LEASE_NEW_REQ:
                        if (redplane_ack_pkt_buf[send_ring_idx].ack_header.ack_type == ack_type_t::LEASE_NEW_ACK)
                        {
                            per_new_latency.push_back(static_cast<uint64_t>(per_packet_dur.count()));
                        }
                        else
                        {
                            per_migrate_latency.push_back(static_cast<uint64_t>(per_packet_dur.count()));
                        }
                        break;
                    case req_type_t::LEASE_RENEW_REQ:
                        if (seq_num != 0)
                        {
                            per_write_latency.push_back(static_cast<uint64_t>(per_packet_dur.count()));
                        }
                        else
                        {
                            per_read_latency.push_back(static_cast<uint64_t>(per_packet_dur.count()));
                        }
                        break;
                    }
                }

                // Update send_ring_idx
                send_ring_idx = (send_ring_idx + 1) % redplane::RawTransport::kSQDepth;
            }

            /////////// DO chain replication
            if (chain_req_pkt != nullptr && chain == true) {
                redplane_req_pkt_buf[chain_send_ring_idx].req_header.seq_num = chain_req_pkt->req_header.seq_num;
                memcpy(&(redplane_req_pkt_buf[chain_send_ring_idx].req_header.flow_key), &(chain_req_pkt->req_header.flow_key), sizeof(req_flow_key_t));
                memcpy(&(redplane_req_pkt_buf[chain_send_ring_idx].req_header.value), &(chain_req_pkt->req_header.value), sizeof(req_value_t));
                memcpy(redplane_req_pkt_buf[chain_send_ring_idx].eth_hdr.dst_mac, &chain_req_pkt->eth_hdr.src_mac, 6);
                raw_transport_chain->tx_one(reinterpret_cast<uint64_t>(&(redplane_req_pkt_buf[chain_send_ring_idx])), sizeof(redplane::eth_hdr_t) + sizeof(req_header_t));
                size_t num_pkts = 0;
                while (1) {
                    num_pkts = raw_transport_chain->rx_burst();
                    if (num_pkts > 0) {
                        raw_transport->post_recvs(num_pkts);
                        break;
                    }
                }
                fprintf(stderr, "Chain acked! %ld\n", num_pkts);
                chain_send_ring_idx = (chain_send_ring_idx + 1) % redplane::RawTransport::kSQDepth;
            }
            //////////////////////
            raw_transport->tx_burst(send_pkt_addr, send_pkt_size, num_pkts);
            send_pkt_addr.clear();
            send_pkt_size.clear();
            stop = std::chrono::high_resolution_clock::now();
        }
        last_rx_ring_idx = (last_rx_ring_idx + num_pkts) % redplane::RawTransport::kNumRxRingEntries;
        total_recvd += num_pkts;
        raw_transport->post_recvs(num_pkts);

        if (unlikely(ctrl_c_pressed == 1))
            break;
    }
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    size_t payload_size = request_size;// - sizeof(req_header_t);
    fprintf(stderr, "(%d): %f Mpps.\n", port_num, static_cast<double>(total_recvd) / (static_cast<double>(duration.count()) / 1000 / 1000) / 1000000);
    fprintf(stderr, "(%d): %f Gbps.\n", port_num, static_cast<double>(total_recvd)*payload_size*8 / (static_cast<double>(duration.count()) / 1000 / 1000) / 1000000000);

    if (m_lat)
    {
        FILE *flat = fopen("latency_log.txt", "w");
        fprintf(flat, "New %ld\n", per_new_latency.size());
        for (size_t i = 0; i < per_new_latency.size(); i++)
        {
            fprintf(flat, "%ld\n", per_new_latency[i]);
        }
        fprintf(flat, "\n");
        fprintf(flat, "Migrate %ld\n", per_migrate_latency.size());
        for (size_t i = 0; i < per_migrate_latency.size(); i++)
        {
            fprintf(flat, "%ld\n", per_migrate_latency[i]);
        }
        fprintf(flat, "\n");
        fprintf(flat, "Write %ld\n", per_write_latency.size());
        for (size_t i = 0; i < per_write_latency.size(); i++)
        {
            fprintf(flat, "%ld\n", per_write_latency[i]);
        }
        fprintf(flat, "\n");
        fprintf(flat, "Read %ld\n", per_read_latency.size());
        for (size_t i = 0; i < per_read_latency.size(); i++)
        {
            fprintf(flat, "%ld\n", per_read_latency[i]);
        }
        fclose(flat);
    }

    munmap(send_buf, redplane::RawTransport::kSendRingSize);
    munmap(send_buf_chain, redplane::RawTransport::kSendRingSize);
}

int main(int argc, char **argv)
{
    signal(SIGINT, ctrl_c_handler);
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    assert(FLAGS_threads <= kNumThreads);

    std::thread req_handler_thread[kNumThreads];

    for (size_t i = 0; i < FLAGS_threads; i++)
    {
        req_handler_thread[i] = std::thread(req_handler, kUDPPort + i + 1, FLAGS_m_lat, FLAGS_chain, FLAGS_nextip);
        bind_to_core(req_handler_thread[i], 0, i+2);
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