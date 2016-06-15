#!/usr/bin/env python

'''
sample usage:
./local_check_system.py -s 'telnet 10.17.145.36' -u admin -o log.1

purpose: check cer system status
1) every 30 seconds, check interface InUti/OutUtil
2) if InUtil > 20% (200Mbps), start data collection
3) run data collection for 5 mins with 5 sec gap
4) collect cpu, protocol pkt stat, cpu packet stat, ....
'''

import os
import sys
import time
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
Usage: 
local_check_system.py -s <session> -u <userid> -p <password> -e <enable_password> -o <output_file>
or
local_check_system.py --session <session> --user <userid> --password <password> --enable <enable_password> --output <output_file>


arguments: 
    -s, --session     session info like "telnet 10.1.1.1" or "ssh -l admin gw1.company.com" 
    -u, --userid      user id
    -p, --password    login password
    -e, --enable      enable password
    -o, --output      output file name
    '''

def parse_stat(output):
    '''
    parse output of "show stat | inc PO|InU", return [[port, in%, out%]]
    telnet@edge0-the.router.uk#show stat e1/1 e1/2 | inc InUti|PORT
    PORT 1/1 Counters: 
    InUtilization             19.48%      OutUtilization             19.46% 
    PORT 1/2 Counters: 
    InUtilization               0.0%      OutUtilization               0.0%
    '''
    port = 'unknown'
    res, inpert, outper = [], 0.0, 0.0
    for line in output.split('\n'):
        a = re.search('PORT\s+(\d+\/\d+)\s+Counters', line)
        if a:
            if port != 'unknown':
                res.append([port, inpert, outper])
            port = a.group(1)

        b = re.search('InUtilization\s+(\d+\.\d+)\%\s+OutUtilization\s+(\d+\.\d+)\%', line)
        if b:
            inpert, outper = map(float, b.groups())

    if port != 'unknown': 
        res.append([port, inpert, outper])

    return res

def collect_data_5min(rtr):
    for i in xrange(60):
        collect_data(rtr)
        print '\n\nNo. %d/60 check, time %d seconds\n\n' % (i+1, (i+1)*5)
        PYSLib.psleep(5, pprint=False)

    print '\n!!!!!!!!!!!!!!!!! 5 min data collection is DONE !!!!!!!!!!!!!!!'
    print '\nNow sleep 5 mins, then re-start monitoring'
    PYSLib.psleep(300)

def collect_data(rtr):
    """
    The script with the below command list has to be run for 5 mins time period  with 5 seconds gap
    So the script needs to run AFTER the issue 
    And the list of commands are
    show lp packet statistics protocol l3 <slot/port>
    show lp packet statistics protocol l2 <slot/port>
    dm pstat
    show cpu histogram hold above 50
    show cpu histogram wait above 50
    dm metro <ppcr id> fabric  counters
    dm metro <ppcr id> qos statistics
    dm metro 0 cnt
    debug packet capture rx and tx with protocol filters 
    """

    rtr.send('!!!! start of data collection - single round !!!!')
    rtr.send('show clock')
    for intf in monitor_ports:
        rtr.send('''
        show lp packet statistics protocol l3 %s
        show lp packet statistics protocol l2 %s
        ''' % (intf[1:], intf[1:])
        )
    rtr.send('''
    show cpu
    show cpu lp
    dm pstat
    ''')

    time.sleep(1)

    rtr.send('''
    show cpu histogram hold above 50 
    show cpu histogram wait above 50
    ''')
    
    rtr.send('''
    rc 1 
    enable 
    skip
    !
    dm metro 0 fabric  counters 
    dm metro 1 fabric  counters 
    dm metro 2 fabric  counters 
    dm metro 0 qos statistics
    dm metro 1 qos statistics
    dm metro 2 qos statistics
    dm metro 0 cnt
    dm metro 1 cnt
    dm metro 2 cnt
    ''')
    rtr.send('debug packet capture rx', set_debug_dest=False, timeout=30)
    rtr.send('debug packet capture tx', set_debug_dest=False, timeout=30)

    rtr.send('''
    exit
    exit''')

    rtr.send('show clock')
    rtr.send('show logg | inc OSPF|VRRP|BGP')
    rtr.send('!!!! end of data collection - single round !!!!')


monitor_ports = ['e1/1', 'e1/5', 'e1/14', 'e1/20']
attack_bw_pert = 20.0

if __name__ == '__main__': 
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], 
            "s:u:p:e:o:", 
            ["session=", "user=", "password=", "enable=", "output="]
            )
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    outfile, session, user, password, enable_password = '', '', '', '', ''

    # parse the sys.argv
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-s', '--session'):
            session = arg
        elif opt in ('-u', '--user'):
            user = arg
        elif opt in ('-p', '--password'):
            password = arg
        elif opt in ('-e', '--enable'):
            enable_password = arg
        elif opt in ('-o', '--output'):
            outfile = arg

    if session == '':
        usage()
        sys.exit(2)

    rtr = pysession(session=session, user=user, password=password, 
            enable_password=enable_password, output_file=outfile)

    total_attack = 0

    while True:
        attacked = False
        attacked_int = []

        o = rtr.send('show stat %s | inc PO|InUti' % ' '.join(monitor_ports))
        for item in parse_stat(o):
            p, i, o = item
            if i > attack_bw_pert:
                attacked_int.append(p)
                attacked = True

        if attacked:
            total_attack += 1
            print '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
            print 'seeing high InUtil(>%.2f%%) on the %d intf: [%s]' %\
                (attack_bw_pert, len(attacked_int), ','.join(attacked_int))
            print 'Now starting the data collection..................'
            print '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
            collect_data_5min(rtr)

        print '###########################################'
        print 'So far we have seen %d times of high InUtil' % total_attack
        print '###########################################'
        PYSLib.psleep(30, pprint=False)

    rtr.send('''
    exit
    exit
    exit
    ''')

