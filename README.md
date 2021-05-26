# RedPlane: Enabling Fault-Tolerant Stateful In-Switch Applications

This is the source code repository of the RedPlane project.
Check out [our paper](https://github.com/daehyeok-kim/redplane-public) for more details.

This repository contains key components to run the RedPlane protocol. 
## Directory Structure

Subdirectory      | Description
------------------| ---------------
`redplane-p4`       | P4 source code for RedPlane-enabled in-switch applications
`redplane-store`       | C++ source code for RedPlane state store
`redplane-tla`       | TLA+ specification of the RedPlane protocol
`scripts`       | Scripts for setup regular switches, servers, and building P4 applications

Each subdirectory includes build instructions for the components.

## System Requirements and Dependencies
We tested the current implementation in the following enviornments:
- **RedPlane P4:** Tofino-based Arista 7170s switch with Intel P4 studio 9.1.1
- **RedPlane state store:** Ubuntu 18.04 with Mellanox OFED 4.7-4.2.9.0

Our testbed consists of two Tofino-based Arista 7170 switches, three Arista 7060CX regular switches, and servers connected as follows:

<img src="/misc/testbed.png" width=30% height=30%>

## Contact
Daehyeok Kim (daehyeok@cs.cmu.edu)
