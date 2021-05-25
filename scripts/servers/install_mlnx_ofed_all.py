#!/usr/bin/python

import os

if __name__ == "__main__":
    os.system ('mkdir -p logs')
    for i in range(20, 31, 1):
        print ('Setup prometheus%s'%(i))
        os.system ('ssh pro%s sudo /h/daehyeok/mlnx_ofed_firmware/MLNX_OFED_LINUX-4.7-3.2.9.0-ubuntu18.04-x86_64/mlnxofedinstall --all --force > logs/setup_log_%s 2>&1'%(i, i))
        os.system ('ssh pro%s sudo /etc/init.d/openibd restart >> logs/setup_log_%s 2>&1'%(i, i))
        print ('End setup prometheus%s'%(i))
