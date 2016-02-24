#!/usr/bin/env python

import re
import sys
import time
from pysession import *

def parse_sh_ip_route_prefix(output):
    """
    telnet@CER1-solomon-1464141#show ip route 3.1.10.3
    Type Codes - B:BGP D:Connected I:ISIS O:OSPF R:RIP S:Static; Cost - Dist/Metric
    BGP  Codes - i:iBGP e:eBGP
    ISIS Codes - L1:Level-1 L2:Level-2
    OSPF Codes - i:Inter Area 1:External Type 1 2:External Type 2 s:Sham Link
    STATIC Codes - d:DHCPv6 
            Destination        Gateway         Port          Cost          Type Uptime src-vrf 
    1       3.1.10.0/24        12.1.10.2       ve 10         1/1           S    14h50m -

    """
    reach_content = False

    for line in output.split('\n'):
        if re.search("^\s+Destination\s+Gateway\s+Port.*", line):
            reach_content = True
            continue

        if not reach_content:
            continue

        # now the line is like:
        # 1       3.1.10.0/24        12.1.10.2       ve 10         1/1           S    14h50m -
        #if re.search("^\d+\s+([0-9\.\/]+)\s+([0-9\.\/]+)", line): 
        return map(str.strip, re.split('\s\s+', line))
    
    return [''] * 8

def ipv4_addr_full_format(ip_addr):
    """
    3.1.1.3 -> 003.001.001.003
    """
    ip_addr = ip_addr.strip()

    re_ipv4_found = re.search('^(\d+)\.(\d+)\.(\d+)\.(\d+)$', ip_addr)

    if re_ipv4_found:
        l = map(int, re_ipv4_found.groups())
        return '%03d.%03d.%03d.%03d' % (l[0], l[1], l[2], l[3])

    return ''

def netmask_to_dot_notation(netmask):
    """
    netmask /n to 255.255.255.0
    """
    netmask = int(netmask)

    dot_mask_list = []
    for i in range(4):
        if netmask >= 8:
            dot_mask_list.append('255')
        elif netmask <= 0:
            dot_mask_list.append('0')
        else:
            dot_mask_list.append(str(2**netmask))

        netmask -= 8
    
    return '.'.join(dot_mask_list)
    
def parse_dm_metro_rc_for_NH_index(output, network, mask_dot):
    """
LP-1#dm metro 0 rc l3 | include 3.1.30.0|NH
|     CAM      |   VPRAM    |VRF|  IP  Addr     |  IP Mask       | NH   | Arp  | A|T
166263;  14984; 0x02000985 ;  0;        3.1.30.0;  255.255.255.0;  2437;   211| 0| 0
    """
    for line in output.split('\n'):
        re_nh_found = re.search('%s\;\s+%s\;\s+(\d+)\;' % (issue_prefix, net_mask_dot), line)

        if re_nh_found:
            return re_nh_found.group(1)

    return ''
    
if __name__ == '__main__': 

    # get the issue prefix
    #issue_dest = '3.1.30.3'
    print '''
###############################################################################
#                                                                             #
#                         Brocade Data Collection Tool                        #
#                                   ver 0.1                                   #
#                                                                             #
#                          Author: solomon@brocade.com                        #
#                                                                             #
###############################################################################
    
    '''

    issue_dest = raw_input('please provide the dest ip of issue prefix: ')

    # get the session info interactively
    cer = pysession()
    #cer = pysession(session='telnet 10.18.24.78')
    cer.pprint=True

    # Part 0. basic info
    o = cer.send("show ip route %s" % issue_dest)

    dummy, issue_prefix, next_hop, oif, cost, prefix_type, prefix_uptime, vrf\
        = parse_sh_ip_route_prefix(o)[:8]

    # get netmask in dot notation
    issue_prefix, net_mask = issue_prefix.split('/')
    net_mask_dot = netmask_to_dot_notation(net_mask)

    print '\n' + pys_lib.pline2('Basic Prefix Info')

    pys_lib.pys_pprint(\
        ['Issue Dest', 'Issue Prefix', 'Net Mask', 'Net Mask Dot', \
         'Next Hop', 'OutIntf', 'Cost', 'Prefix Type', 'Prefix Uptime', \
         'Prefix VRF'],
        [issue_dest, issue_prefix, net_mask, net_mask_dot, next_hop, oif, 
         cost, prefix_type, prefix_uptime, vrf])

    # Part 1, MP commands
    print '\n' + pys_lib.pline2('Part 1, MP commands')

    cer.send("skip")
    cer.send("show clock")
    cer.set_debug_dest_to_me()
    cer.send("show tech-support", timeout=60)
    #cer.send("ping %s" % issue_dest, timeout=30)
    cer.send("dm pstat")
    cer.send("show arp %s debug" % next_hop)
    cer.send("show ip arp-mac-entries")
    pys_lib.psleep(120, ' 2nd dm pstat')
    cer.send("dm pstat")

    # Part 2, LP commands
    print '\n' + pys_lib.pline2('Part 2, LP commands')

    cer.send("rconsole 1")
    cer.send("enable")
    cer.send("skip")
    cer.send("show ip arp-mac")
    cer.send("show arp %s debug" % next_hop)
    cer.send("show ip cache")
    cer.send("show ip cache %s" % issue_prefix)
    cer.send("show ip route", timeout=180)
    cer.send("show ip route %s" % issue_prefix)
    cer.send("show ip next-hop %s" % issue_prefix)
    cer.send("show ip next-hop %s debug" % issue_prefix)
    cer.send("dm metro 0 lpm | include %s" % ipv4_addr_full_format(issue_prefix))
    cer.send("show ip lpm debug %s" % issue_prefix)

    output = cer.send("dm metro 0 rc l3 | include %s" % issue_prefix, timeout=300)
    nh_index = parse_dm_metro_rc_for_NH_index(output, issue_prefix, net_mask_dot)

    cer.send("dm metro 0 table nexthop %s detail" % nh_index)

    # Part 3, DEBUG commands
    print '\n' + pys_lib.pline2('Part 3, DEBUG commands')

    cer.send("debug ip next-hop")
    cer.send("debug ip arp %s" % next_hop)
    cer.send("debug ip arp-mac")
    cer.send("debug ip rtm %s" % issue_prefix)
    cer.send("debug ip cache")
    cer.send("debug ip lpm")
    cer.send("debug ip static-cam")

    cer.send("debug ip rtm nexthop")
    
    pys_lib.psleep(300, 'waiting for debug output')
    cer.send("\n")
    #print '\n\n' + '-' * 80 + '\n' + o + '\n' + '=' * 80

    pys_lib.psleep(300, 'waiting for debug output')
    cer.send("\n")
    #print '\n\n' + '-' * 80 + '\n' + o + '\n' + '=' * 80

    pys_lib.psleep(300, 'waiting for debug output')
    o = cer.send("\n")
    #print '\n\n' + '-' * 80 + '\n' + o + '\n' + '=' * 80

    cer.send("no debug all")
    cer.send("exit")
    cer.send("no debug all")
    cer.send("exit")
    cer.send("no debug all")
    
    print '\n' + pys_lib.pline2('END OF DATA COLLECTION')
