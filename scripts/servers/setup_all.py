#!/usr/bin/python

import logging
import threading
import os

if __name__ == "__main__":
    os.system ('mkdir -p logs')
    for i in range(19, 31, 1):
        print ('Setup prometheus%s'%(i))
        os.system ('ssh pro%s /h/daehyeok/redplane-dev/scripts/servers/setup_hugepages.sh > logs/setup_log_%s 2>&1'%(i, i))
        os.system ('ssh pro%s /h/daehyeok/redplane-dev/scripts/servers/setup_packages.sh >> logs/setup_log_%s 2>&1'%(i, i))
        if i in [26, 24, 22]:
            os.system ('ssh pro%s sudo ifconfig ens1 mtu 9000' % (i))
        print ('End setup prometheus%s'%(i))

