#!/usr/bin/env python

'''
This script is to save/load configuration on a testbed of Brocade NetIron rotuer

Usage: load_testbed.py -a <action> -c <testbed_cfg_file> -d <cfg_dir> -t <tftp_svr_ip>

arguments: 
    -a, --action   action: save|load
    -d, --dir      config directory
    -f, --tftp     tftp server ip 
    -c, --testbed  test config file, which contains test info in format like
--------------------------------------
# session info;      cfg file name; intf; intf_ip_addr; 
# ================== ============== =====
telnet 10.1.1.1;       router1; 
telnet 10.1.1.2 3001;  router2;
--------------------------------------

for example
load_testbed.py -a save -c StaticLab.list -d configSave/StaticLab/working -t 10.24.144.5
'''

import os
import sys
import getopt
import threading

try: 
    from pysession import *
except:
    try: 
        sys.path.insert(1, os.path.join(sys.path[0], '..'))
        from pysession import *
    except:
        sys.stderr.write("Error: can't import pysession module\n")
        exit(1)


def usage():
    print '''
Usage: load_testbed.py -a <action> -c <testbed_cfg_file> -d <cfg_dir> -t <tftp_svr_ip>

arguments: 
    -a, --action   action: save|load
    -c, --testbed  test config file, which contains session info and config file names, like
    --------------------------------------
    telnet 10.1.1.1; router1
    telnet 10.1.1.2 3001; router2
    --------------------------------------
    -d, --dir      config directory
    -f, --tftp     tftp server ip 
    '''
 
#def work_router(action='copy', session='', intf='man 1', tftp_ip='', cfg_file='', ip='', mask='', gw=''):
def work_router(action, session, intf, tftp_ip, cfg_file, ip, mask, gw):
    # establish session
    rtr = pysession(session=session)

    rtr.send(''' 
        enable 
        conf term 
        int %s 
        ip addre %s %s
        enable
        exit 
        ip route %s 255.255.255.255 %s 
        end
        ''' % (intf, ip, mask, tftp_ip, gw)
        )

    if action == 'reload': 
        
        cmd = 'copy tftp startup-config %s %s' % (tftp_ip, cfg_file)
        rtr.send(cmd)
        time.sleep(5) 
        rtr.send('reload')
    elif action == 'save':
        cmd = 'copy run tftp %s %s' % (tftp_ip, cfg_file)
        rtr.send(cmd)

 
if __name__ == '__main__': 
    try:
        opts, args = getopt.getopt(sys.argv[1:], "a:f:d:t:", 
            ["action=", "file=", "dir=", "tftp="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    testbedF, action, cfgdir, tftp= 'testbed.local', 'load', 'SLBase', '10.18.10.123'

    # parse the sys.argv
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-a', '--action'):
            action = arg
        elif opt in ('-f', '--file'):
            testbedF = arg
        elif opt in ('-d', '--dir'):
            cfgdir = arg
        elif opt in ('-t', '--tftp'):
            tftp = arg
  
    lines = []
    try: 
        with open(testbedF, 'r') as f:
            lines = f.readlines()
        f.close()
    except IOError:
        print 'Error to open testbed cfg file - %s, script exiting.....' % testbedF
        sys.exit(1)

    for line in lines:
        line = line.strip()

        if len(line)==0 or line[0] == '#':
            continue

        session, cfgfile, intf, intf_ip, intf_mask, \
                gw = map(str.strip, line.split(';'))
        print session, cfgfile, intf, intf_ip, intf_mask, gw 
        
        #def work_router(action, session, intf, tftp_ip, cfg_file, ip, mask, gw):
        t = threading.Thread(target=work_router, args=(action, session, intf, tftp, \
                '%s/%s' % (cfgdir, cfgfile), intf_ip, intf_mask, gw))
        t.start()
