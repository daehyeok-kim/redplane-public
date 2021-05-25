#include "common.h"

DEFINE_uint32(num_sessions, 1, "Number of UDP sessions");
DEFINE_uint32(req_size, 0, "Request size (excluding Ethernet, IP, UDP headers)");
DEFINE_uint32(req_num, 0, "Number of requests (0: infinite)");