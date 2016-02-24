#!/usr/bin/env python

import re
import os
import sys
import time
import getopt
from pysession import *

def read_cmd_file(cmdfile):
    list_cmd = []

    with open(cmdfile) as f:
        for line in f:
            line1 = line.strip()

            if line1 == '' or line1[0]=='#':
                continue

            list_cmd.append(line.rstrip())

    return '\n'.join(list_cmd)

def usage():
    print '''
Usage: BrcdDataCollector.py -C <cmdfile> -s <session> -i <userid> [-p <password>] [-e <enable_password]

arguments:
    -C, --cmdfile          command file containing list of commands send to router
    -s, --session          session info like "telnet 10.1.1.1" or "ssh -l admin gw1.company.com"
    -u, --userid           user id
    -p, --password         login password of user id (you can leave it blank and provide it later in non-echo way)
    -e, --enable_password  enable password (you can leave it blank and provide it later in non-echo way)
    -o, --output           output file name
    '''

def print_header():
    print r'''
/##############################################################################\
#                          Brocade Data Collection Tool                        #
#                                    ver 0.1                                   #
#                           Author: solomon@brocade.com                        #
\##############################################################################/
    '''

if __name__ == '__main__': 
    try:
        opts, args = getopt.getopt(sys.argv[1:], "C:S:s:u:p:e:o:", 
            ["cmdfile=", "sessfile=", "session=", "userid=", "password=",\
             "enable_password=", "output="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    # initialize the variables
    all_commands = ''
    session, userid, password, enable_password, output_file = '', '', '', '', ''

    # parse the sys.argv
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-C', '--cmdfile'):
            all_commands = read_cmd_file(arg)
        elif opt in ('-S', '--sessfile'):
            sessfile = arg
            # not completed yet
        elif opt in ('-s', '--session'):
            session = arg
        elif opt in ('-u', '--userid'):
            userid = arg
        elif opt in ('-p', '--password'):
            password = arg
        elif opt in ('-o', '--output'):
            output_file = arg
        elif opt in ('-e', '--enable_password'):
            enable_password = arg

    if all_commands == '':
        print "Error: no commands specified!!!!!"
        usage()
        sys.exit(2)

    print_header()

    print '\n' + PYSLib.pline1('SESSION INFO')
    print "Session: %s" % session
    print "User ID: %s" % userid
    print PYSLib.pline1('Press Enter to continue ......')
    dummy = raw_input("")

    print '\n' + PYSLib.pline1('LIST OF COMMANDS')
    print all_commands
    print PYSLib.pline1('Press Enter to start......')
    dummy = raw_input("")

    router = pysession(session=session, user=userid, password=password, 
        enable_password=enable_password, log_file_prefix='brcd__', 
        output_file=output_file)

    router.pprint=True 
    
    router.send(all_commands)

    total_sec = int(time.time() - router.start_time)
    elapse_time = '%d min %d sec' % (total_sec/60, total_sec%60)

    sleep_time = '%d min %d sec' % (router.sleep_time/60, router.sleep_time%60)

    file_size_in_KB = '%d KB' % int(os.stat(router.log_file_name).st_size/1000)

    print '\n' + PYSLib.pline2('DATA COLLECTION SUMMARY')
    print '       script running time :', elapse_time
    print '             sleeping time :', sleep_time
    print '           number of lines :', router.counter_line
    print '        number of commands :', router.counter_cmd
    print 'number of invalid commands :', router.counter_invalid_cmd
    print '   size of log output file :', file_size_in_KB
    print PYSLib.pline2('END OF DATA COLLECTION')
    
