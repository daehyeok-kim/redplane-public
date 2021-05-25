#!/bin/sh
sudo apt-get update
sudo apt-get -y install g++ cmake make flowgrind qperf netpipe-tcp

sudo apt-get -y install libnuma-dev libgflags-dev libgtest-dev
(cd /usr/src/gtest && sudo cmake . && sudo make && sudo mv libg* /usr/lib/)
