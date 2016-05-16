#!/usr/bin/env python

'''
This script is to reload Brocade NetIron rotuer

1) start session to router via console
2) copy tftp startup-config 10.18.10.123 SLBase/cfg.mlx1
3) reload
4) session after 3 min sleep
'''

import sys
import getopt
from pysession import *

def reload_brcd_ni(session='', tftp_ip='', cfg_file='', ip='', mask='', gw=''):
    rtr = pysession(session=session)

    if ip != '':
        rtr.send('''
            enable
            conf term
            int management 1
            ip addre %s/%s
            exit
            ip route %s 255.255.255.255 %s
            end
        ''' % (ip, mask, tftp_ip, gw))
    rtr.send('copy tftp startup-config %s %s' % (tftp_ip, cfg_file))
    time.sleep(5)
    rtr.send('reload')
 
def usage():
    print '''
Usage: reload_brcd_ni.py -c <cfgfile> -s <session> -t <tftpsvr>

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
