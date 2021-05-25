#include <string>
#include <iostream>
#include <sys/mman.h>
#include <gflags/gflags.h>
#include <signal.h>
#include <thread>
#include <chrono>
#include <numa.h>
#include <unordered_map>
#include "raw_transport/raw_transport.h"
#include "redplane_header.h"

DEFINE_uint32(threads, 1, "Number of workers");
DEFINE_string(nextip, "198.19.11.0", "Next server IP");

static constexpr uint16_t kUDPPort = 8000;
static constexpr uint16_t kSwitchUDPPort = 4000;
static constexpr uint16_t kNumThreads = 20;
static constexpr uint16_t kLeasePeriod = 5;
static const size_t kPhyPorts = 1; // Number of physical ports in CX-5 NIC

// Globals
volatile sig_atomic_t ctrl_c_pressed = 0;
void ctrl_c_handler(int) { ctrl_c_pressed = 1; }

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

static uint16_t ip_checksum(const redplane::ipv4_hdr_t *buf, size_t hdr_len)
{
  unsigned long sum = 0;
  const uint16_t *ip1;

  ip1 = reinterpret_cast<const uint16_t *>(buf);
  while (hdr_len > 1)
  {
    sum += *ip1++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    hdr_len -= 2;
  }

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return (~sum);
}

void print_bytes(uint8_t *buffer)
{
  size_t k, j, base;
  for (base = 0; base < 1; base++)
  {
    for (k = base * 256; k < (base * 256) + 256; k += 16)
    {
      for (j = 0; j < 15; j++)
      {
        fprintf(stderr, "%02x ", *(buffer + k + j));
      }
      fprintf(stderr, "%02x\n", *(buffer + k + j));
    }
    fprintf(stderr, "\n");
  }
  fprintf(stderr, "\n");
}