# RedPlane state store

Our state store implementation is built based on Mellanox's Raw ethernet verbs library and tested on Ubuntu 18.04 system with Mellanox ConnectX-5 NICs. 
It is compatible with `MLNX_OFED_LINUX-4.7-3.2.9.0`. 

## Build Instructions
1. Create a build folder
```bash
redplane-store$ mkdir build && cd build
```
2. Build the applications using cmake
```bash
build$ cmake .. && make
```

## Acknowledgement
We implemented the raw transport library based on the transport implementation in the [eRPC](https://github.com/erpc-io/eRPC) project.
