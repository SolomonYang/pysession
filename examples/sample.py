#!/usr/bin/env python

'''
sample script, 
1) read configuration lines from a file
2) apply them to device
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
Usage: sample.py -c <cfgfile> -s <session>

arguments: 
    -c, --cfgfile     router configuration file
    -s, --session     session info like "telnet 10.1.1.1" or "ssh -l admin gw1.company.com" 
    '''
 
if __name__ == '__main__': 
    try:
        opts, args = getopt.getopt(sys.argv[1:], "s:t:c:i:m:g:", 
            ["session=", "tftpsvr=", "cfgfile=", "ip=", "mask=", "gw="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    session, cfg_file = '', ''

    # parse the sys.argv
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-c', '--cfgfile'):
            cfg_file = arg
        elif opt in ('-s', '--session'):
            session = arg
    
    if session == '' or cfg_file == '':
        usage()
        sys.exit(2)

    try:
        with open(cfg_file, 'r') as f:
            lines = f.readlines()
    except IOError:
        print 'Failed to open config file, exit......' 
        sys.exit(1)

    rtr = pysession(session=session)

    for line in lines:
        line = line.strip()

        rtr.send(line)
