#!/usr/bin/env python

'''
sample script
'''

import os
import sys
import getopt

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
Usage: sample.py -c <cfgfile> -s <session> -t <tftpsvr>

arguments: 
    -c, --cfgfile     router configuration file
    -s, --session     session info like "telnet 10.1.1.1" or "ssh -l admin gw1.company.com" 
    -t, --tftsvr      tftp server ip 
    -i, --ip          management ip 
    -m, --mask        management ip mask
    -g, --gw          gateway
    '''
 
if __name__ == '__main__': 
    try:
        opts, args = getopt.getopt(sys.argv[1:], "s:t:c:i:m:g:", 
            ["session=", "tftpsvr=", "cfgfile=", "ip=", "mask=", "gw="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    session, tftp_ip, cfg_file = '', '', ''
    ip, mask, gw = '', '', ''

    # parse the sys.argv
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-c', '--cfgfile'):
            cfg_file = arg
        elif opt in ('-s', '--session'):
            session = arg
        elif opt in ('-t', '--tftpsvr'):
            tftp_ip = arg
        elif opt in ('-i', '--ip'):
            ip = arg
        elif opt in ('-m', '--mask'):
            mask = arg
        elif opt in ('-g', '--gw'):
            gw = arg
    
    if session == '' or tftp_ip == '' or cfg_file == '':
        usage()
        sys.exit(2)

    reload_brcd_ni(session=session, tftp_ip=tftp_ip, cfg_file=cfg_file, 
        ip=ip, mask=mask, gw=gw)
