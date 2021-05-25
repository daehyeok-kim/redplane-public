#include "receiver.h"

void run_receiver(bool process_req, bool batch)
{
    uint8_t *send_buf = static_cast<uint8_t *>(mmap(NULL, redplane::RawTransport::kRingSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0));
    if (send_buf == MAP_FAILED)
    {
        std::ostringstream xmsg; // The exception message
        xmsg << "Hugepage map failed ";
        throw std::runtime_error(xmsg.str());
    }
    memset(send_buf, 0, redplane::RawTransport::kRingSize);
    redplane::RawTransport *raw_transport = new redplane::RawTransport(kUDPPort, kPhyPorts, send_buf, redplane::RawTransport::kRingSize);
    uint8_t **rx_ring = raw_transport->getRxRing();

    if (process_req)
    {
        // Get a routing info and fill in packet headers
        struct redplane::RawTransport::RoutingInfo local_ri;
        raw_transport->fill_local_routing_info(&local_ri);

        redplane::eth_hdr_t eth_hdr;
        redplane::ipv4_hdr_t ipv4_hdr;
        redplane::udp_hdr_t udp_hdr;

        auto *ri = reinterpret_cast<redplane::eth_routing_info_t *>(&local_ri);
        memcpy(eth_hdr.src_mac, ri->mac, 6);
        memcpy(eth_hdr.dst_mac, &kReturnMacAddr, 6);
        eth_hdr.eth_type = htons(redplane::kIPEtherType);
        ipv4_hdr.src_ip = htonl(ri->ipv4_addr);
        ipv4_hdr.dst_ip = redplane::ipv4_from_str(kReturnIpAddr.c_str());
        ipv4_hdr.version = 4;
        ipv4_hdr.ihl = 5;
        ipv4_hdr.ecn = 1;
        ipv4_hdr.dscp = 0;
        ipv4_hdr.tot_len = htons(sizeof(redplane::ipv4_hdr_t) + sizeof(redplane::udp_hdr_t));
        ipv4_hdr.id = htons(0);
        ipv4_hdr.frag_off = htons(0);
        ipv4_hdr.ttl = 128;
        ipv4_hdr.protocol = redplane::kIPHdrProtocol;
        ipv4_hdr.check = 0;
        udp_hdr.src_port = htons(8000);
        udp_hdr.dst_port = htons(kUDPPort);
        udp_hdr.len = htons(sizeof(redplane::udp_hdr_t));
        udp_hdr.check = 0;

        memcpy(send_buf, &eth_hdr, sizeof(redplane::eth_hdr_t));
        memcpy(send_buf + sizeof(redplane::eth_hdr_t), &ipv4_hdr, sizeof(redplane::ipv4_hdr_t));
        memcpy(send_buf + sizeof(redplane::eth_hdr_t) + sizeof(redplane::ipv4_hdr_t), &udp_hdr, sizeof(redplane::udp_hdr_t));
    }
    size_t total_recvd = 0;
    size_t total_recvd_bytes = 0;
    size_t last_rx_ring_idx = 0;
    redplane_test_pkt_t *test_pkt;

    auto start = std::chrono::high_resolution_clock::now();
    auto stop = std::chrono::high_resolution_clock::now();

    while (1)
    {
        size_t num_pkts = raw_transport->rx_burst();
        if (num_pkts > 0)
        {
            stop = std::chrono::high_resolution_clock::now();
            if (total_recvd == 0)
            {
                start = std::chrono::high_resolution_clock::now();
            }

            for (size_t i = last_rx_ring_idx; i < last_rx_ring_idx + num_pkts; i++)
            {
                size_t idx = i % redplane::RawTransport::kNumRxRingEntries;
                test_pkt = reinterpret_cast<redplane_test_pkt_t *>(rx_ring[idx]);
                if (process_req && batch == false)
                {
                    redplane_test_state_store[test_pkt->replane_kv.state_key] = test_pkt->replane_kv.state_value;
                    //raw_transport->tx_one(reinterpret_cast<uint64_t>(send_buf), sizeof(redplane::eth_hdr_t) + sizeof(redplane::ipv4_hdr_t) + sizeof(redplane::udp_hdr_t));
                }
                total_recvd_bytes += ntohs(test_pkt->ipv4_hdr.tot_len);
            }
            if (process_req == true && batch == true)
            {
                redplane_test_state_store[test_pkt->replane_kv.state_key] = test_pkt->replane_kv.state_value;
                //raw_transport->tx_one(reinterpret_cast<uint64_t>(send_buf), sizeof(redplane::eth_hdr_t) + sizeof(redplane::ipv4_hdr_t) + sizeof(redplane::udp_hdr_t));
            }
            last_rx_ring_idx = (last_rx_ring_idx + num_pkts) % redplane::RawTransport::kNumRxRingEntries;
            total_recvd += num_pkts;
            raw_transport->post_recvs(num_pkts);
        }
        if (unlikely(ctrl_c_pressed == 1))
            break;
    }
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);

    fprintf(stderr, "%ld packets received during %f seconds.\n", total_recvd, static_cast<double>(duration.count()) / 1000 / 1000);
    fprintf(stderr, "%f Mreqs/seconds.\n", static_cast<double>(total_recvd) / (static_cast<double>(duration.count()) / 1000 / 1000) / 1000000);
    fprintf(stderr, "%f Gbits/seconds.\n", static_cast<double>(total_recvd_bytes) * 8 / (static_cast<double>(duration.count()) / 1000 / 1000) / 1000000000);
    munmap(send_buf, redplane::RawTransport::kRingSize);
}

int main(int argc, char **argv)
{
    signal(SIGINT, ctrl_c_handler);
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    std::thread receiver_thread;
    receiver_thread = std::thread(run_receiver, FLAGS_process_req, FLAGS_batch);
    bind_to_core(receiver_thread, 0, 1);

    while (1)
    {
        std::chrono::milliseconds dura(2000);
        std::this_thread::sleep_for(dura);
        if (unlikely(ctrl_c_pressed == 1))
            break;
    }

    receiver_thread.join();

    return 0;
}