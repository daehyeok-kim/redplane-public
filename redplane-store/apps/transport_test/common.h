#include <string>
#include <iostream>
#include <sys/mman.h>
#include <gflags/gflags.h>
#include <signal.h>
#include <thread>
#include <chrono>
#include <numa.h>
#include <map>
#include <unordered_map>
#include "raw_transport/raw_transport.h"

// Globals
volatile sig_atomic_t ctrl_c_pressed = 0;
void ctrl_c_handler(int) { ctrl_c_pressed = 1; }

struct redplane_test_key_t 
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct redplane_test_kv_t
{
  //redplane_test_key_t state_key;
  uint32_t state_key;
  uint32_t state_value;
};

std::map <uint32_t, uint32_t> redplane_test_state_store;

struct redplane_test_pkt_t
{
  redplane::eth_hdr_t eth_hdr;
  redplane::ipv4_hdr_t ipv4_hdr;
  redplane::udp_hdr_t udp_hdr;
  redplane_test_kv_t replane_kv;
  uint8_t data[redplane::RawTransport::kRecvSize-sizeof(redplane::eth_hdr_t)-sizeof(redplane::ipv4_hdr_t)-sizeof(redplane::udp_hdr_t)-sizeof(redplane_test_kv_t)];
};

static const std::string kReceiverIpAddr = "11.0.0.20";                          // Prometheus 20
static const std::string kReturnIpAddr = "11.0.0.21";                          // Prometheus 21
static const uint8_t kReceiverMacAddr[6] = {0xb8, 0x83, 0x03, 0x79, 0xaf, 0x30}; // Prometheus 20
static const uint8_t kReturnMacAddr[6] = {0xb8, 0x83, 0x03, 0x70, 0x88, 0xb4}; // Prometheus 21
static const size_t kPhyPorts = 1;                                               // Number of physical ports in CX-5 NIC

static constexpr uint16_t kUDPPort = 3001;

static std::vector<size_t>
get_lcores_for_numa_node(size_t numa_node)
{
  assert(numa_node <= static_cast<size_t>(numa_max_node()));

  std::vector<size_t> ret;
  size_t num_lcores = static_cast<size_t>(numa_num_configured_cpus());

  for (size_t i = 0; i < num_lcores; i++)
  {
    if (numa_node == static_cast<size_t>(numa_node_of_cpu(i)))
    {
      ret.push_back(i);
    }
  }

  return ret;
}

static void bind_to_core(std::thread &thread, size_t numa_node, size_t numa_local_index)
{
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  assert(numa_node <= static_cast<size_t>(numa_max_node()));

  auto lcore_vec = get_lcores_for_numa_node(numa_node);
  size_t global_index = lcore_vec.at(numa_local_index);

  CPU_SET(global_index, &cpuset);
  int rc = pthread_setaffinity_np(thread.native_handle(), sizeof(cpu_set_t),
                                  &cpuset);
  assert(rc == 0);
}