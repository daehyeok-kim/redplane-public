# RedPlane-enabled P4 applications

We built and tested our implementation with Tofino-baed Arista 7170 switches and Intel P4 Studio 9.1.1.

## Build Instructions
1. Set up the P4 studio SDE environment variables. For example, run the following command in the bf-sde-9.1.1 directory in your system, 
```bash
bf-sde-9.1.1$ . $PROJ_ROOT/scripts/set_sde.sh
```
2. Compile each P4 application using the build script included in `scripts`. For example, to build RedPlane-enabled NAT,
```bash
nat_dir$ $PROJ_ROOT/scripts/p4_build.sh nat_redplane.p4
```
