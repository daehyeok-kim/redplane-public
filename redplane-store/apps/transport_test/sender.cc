#include "sender.h"

std::thread sender_thread[20];
size_t per_thread_sent[20];

void run_sender(size_t idx, size_t req_size, size_t req_num)
{
    // Initialize the memory region for SENDs
    uint8_t *send_buf = static_cast<uint8_t *>(mmap(NULL, redplane::RawTransport::kRingSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0));
    if (send_buf == MAP_FAILED)
    {
        std::ostringstream xmsg; // The exception message
        xmsg << "Hugepage map failed ";
        throw std::runtime_error(xmsg.str());
    }
    memset(send_buf, 0, redplane::RawTransport::kRingSize);
    redplane::RawTransport *raw_transport = new redplane::RawTransport(kUDPPort, kPhyPorts, send_buf, redplane::RawTransport::kRingSize);

    // Get a routing info and fill in packet headers
    struct redplane::RawTransport::RoutingInfo local_ri;
    raw_transport->fill_local_routing_info(&local_ri);

    redplane::eth_hdr_t eth_hdr;
    redplane::ipv4_hdr_t ipv4_hdr;
    redplane::udp_hdr_t udp_hdr;

    uint8_t *data = static_cast<uint8_t*>(malloc(req_size + sizeof(redplane_test_kv_t)));
    memset(data, 0, req_size + sizeof(redplane_test_kv_t));

    auto *ri = reinterpret_cast<redplane::eth_routing_info_t *>(&local_ri);
    memcpy(eth_hdr.src_mac, ri->mac, 6);
    memcpy(eth_hdr.dst_mac, &kReceiverMacAddr, 6);
    eth_hdr.eth_type = htons(redplane::kIPEtherType);
    ipv4_hdr.src_ip = htonl(ri->ipv4_addr);
    ipv4_hdr.dst_ip = redplane::ipv4_from_str(kReceiverIpAddr.c_str());
    ipv4_hdr.version = 4;
    ipv4_hdr.ihl = 5;
    ipv4_hdr.ecn = 1;
    ipv4_hdr.dscp = 0;
    ipv4_hdr.tot_len = htons(sizeof(redplane::ipv4_hdr_t) + sizeof(redplane::udp_hdr_t) + req_size);// + sizeof(redplane_test_kv_t));
    ipv4_hdr.id = htons(0);
    ipv4_hdr.frag_off = htons(0);
    ipv4_hdr.ttl = 128;
    ipv4_hdr.protocol = redplane::kIPHdrProtocol;
    ipv4_hdr.check = 0;
    udp_hdr.src_port = htons(8000 + idx);
    udp_hdr.dst_port = htons(kUDPPort);
    udp_hdr.len = htons(sizeof(redplane::udp_hdr_t) + req_size);// + sizeof(redplane_test_kv_t));
    udp_hdr.check = 0;

    memcpy(send_buf, &eth_hdr, sizeof(redplane::eth_hdr_t));
    memcpy(send_buf + sizeof(redplane::eth_hdr_t), &ipv4_hdr, sizeof(redplane::ipv4_hdr_t));
    memcpy(send_buf + sizeof(redplane::eth_hdr_t) + sizeof(redplane::ipv4_hdr_t), &udp_hdr, sizeof(redplane::udp_hdr_t));
    memcpy(send_buf + sizeof(redplane::eth_hdr_t) + sizeof(redplane::ipv4_hdr_t) + sizeof(redplane::udp_hdr_t), data, req_size);// + sizeof(redplane_test_kv_t));

    fprintf(stderr, "Thread %ld: ready to send\n", idx);
    per_thread_sent[idx] = 0;
    while (1)
    {
        raw_transport->tx_one(reinterpret_cast<uint64_t> (send_buf), sizeof(redplane::eth_hdr_t) + sizeof(redplane::ipv4_hdr_t) + sizeof(redplane::udp_hdr_t) + req_size);// + sizeof(redplane_test_kv_t));
        per_thread_sent[idx]++;
        if (unlikely(ctrl_c_pressed == 1))
            break;
        if (per_thread_sent[idx] == req_num)
            break;
    }
    
    fprintf(stderr, "Thread %ld: Sent %ld\n", idx, per_thread_sent[idx]);
    munmap(send_buf, redplane::RawTransport::kRingSize);
}

int main(int argc, char **argv)
{
    signal(SIGINT, ctrl_c_handler);
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    fprintf(stderr, "Num UDP flows: %d\tRequest size: %d\n", FLAGS_num_sessions, FLAGS_req_size);

    assert(FLAGS_num_sessions <= 20);

    for (size_t i = 0; i < FLAGS_num_sessions; i++)
    {
        sender_thread[i] = std::thread(run_sender, i, FLAGS_req_size, FLAGS_req_num);
        bind_to_core(sender_thread[i], 0, i);
    }

    while (1)
    {
        std::chrono::milliseconds dura(2000);
        std::this_thread::sleep_for(dura);
        if (unlikely(ctrl_c_pressed == 1))
            break;
    }

    size_t total_sent = 0;
    for (size_t i = 0; i < FLAGS_num_sessions; i++)
    {
        sender_thread[i].join();
        total_sent += per_thread_sent[i];
    }
    fprintf(stderr, "Total sent %ld\n", total_sent);
    return 0;
}