"""
Base class for pysession
1) Define network devices and store necessary varibles like connection, 
   ip, protocol, port, username, password, enable_password etc.
2) Initialize Telnet/Console/SSH connections to network devices
3) Provide a simplified API interface to user application and hide low-level 
   connection interactions
4) Support multi vendor OS's/devices - Cisco IOS/XR/NxOS, Brocade Netiron, etc
"""

import re
import sys
import time
import getpass
import pexpect

__device_version__ = '0.1'

MAX_READ = 163840

# --------------------------------------------------------------------------- #
# default values, which can be changed accordingly. For example, all of 
# routers use same username and password, you don't specify it repeatedly 
# when defining session. Just change the default values
#
# DEFAULT_SHORT_TIMEOUT, pexpect uses 30 seconds. We use 10 sec instead. 
# DEFAULT_DEVICE_TYPE, given as 'router' then pysession will try to enable 
#     and page off session by sending "term len 0" and "skip"
# --------------------------------------------------------------------------- #
DEFAULT_USERNAME = None
DEFAULT_PASSWORD = None
DEFAULT_ENABLE_PASSWORD = None
DEFAULT_SHORT_TIMEOUT = 10
DEFAULT_DEVICE_TYPE = 'router'

# --------------------------------------------------------------------------- #
# debug msg level
# --------------------------------------------------------------------------- #
DEBUG_MSG_VERBOSE = 9
DEBUG_MSG_WARNING = 3
DEBUG_MSG_INFO    = 2
DEBUG_MSG_ERROR   = 1
DEBUG_MSG_CRITICAL= 0

# --------------------------------------------------------------------------- #
class pysession:
    """
    Basic class for pysession, e.g.
    rtr1 = pysession(session='telnet 10.1.1.1')         ; telnet vty
    rtr2 = pysession(session='telnet 10.1.1.1 2001')    ; telnet console
    rtr3 = pysession(session='ssh -l user 10.1.1.1')    ; ssh 
    """

    # ----------------------------------------------------------------------- #
    def __init__(self, 
                 session=None,
                 user=DEFAULT_USERNAME, 
                 password=DEFAULT_PASSWORD, 
                 enable_password=DEFAULT_ENABLE_PASSWORD, 
                 device_type=DEFAULT_DEVICE_TYPE, 
                 device_os='', 
                 device_version='', debug_level=0):

        # internal variables
        self.prompt_line = None

        # connection info
        self.sesion = session.strip()

        # login credential 
        self.user = user
        self.password = password
        self.enable_password = enable_password

        # device info
        self.device_type = device_type
        self.device_os = device_os
        self.device_version = device_version
       
        # Device    CRLF
        # ========  ====
        # Default   \r
        # PC/Linux  \r\n
        # Cisco/IOS \r\n
        #
        # CRLF: use '\r' instead of os.linesep, working with Brocade/IOS
        # Do I need to write a function to try '\r' or '\r\n' to figure out
        # the exact CRLF?
        # 
        # Cisco IOS Terminal Services Cmd Ref, Rel 12.2
        # "Configures the Cisco IOS software to send a CARRIAGE RETURN (CR)
        #  as a CR followed by a NULL instead of a CR followed by a LINE 
        #  FEED (LF)."
        # So Cisco/IOS uses \r\n
        #
        self.CRLF = '\r'
        if re.search('pc|linux', self.device_type, re.IGNORECASE): 
            self.CRLF = '\r\n'
        if re.search('ios|cisco', self.device_os, re.IGNORECASE): 
            self.CRLF = '\r\n'

        # debug level, the higher, the more verbose, default is 0, which 
        # means none debug
        self.debug_level = debug_level

        #
        # at the beginning, w/o knowledge of hostname, we use 3 possible 
        # prompts
        # '#' : enable mode of router/switch
        # '>' : login mode of router/switch
        # '$' : login prompt of linux
        #
        self.prompt_list = ['#', '>', '\$']

        # real pyexpect instance of router connection
        self.child = None

        self.collect_sysinfo()

        if self.connect() == -1:
            print 'Error to start session to %s' % self.session
            print self.__str__()
            return 

        
        self.post_session()

    # ----------------------------------------------------------------------- #
    def print_debug_message(self, msg, msg_level=DEBUG_MSG_VERBOSE):
        """
        common debug print, only print the msg with level <= self.debug_level
        """
        if self.debug_level >= msg_level:
            print '\n' + msg

    # ----------------------------------------------------------------------- #
    def __str__(self):
        str = '----------- pysession Details -----------\n'
        str += pys_pprint(
            ['connection', 'user', 'password', 'enable_passord', \
             'device_type', 'os', 'device_version', \
             'output before', 'output after'],
            [self.conn, self.user, self.password, self.enable_password,
             self.device_type, self.device_os, self.device_version,\
             self.child.before, self.child.after],
            action="str")
        return str

    # ----------------------------------------------------------------------- #
    def get_session_interactive(self): 
        """
        if session info invalid, need to call this method to get session 
        interactivly
        """
        session = raw_input("""
Please provide the session info to device, like "telnet 10.1.1.1" or "ssh -l user host1.comapny.com"
session info: """)
        
        if self.debug_level:
            print session

    # ----------------------------------------------------------------------- #
    def sendline(self, cmd): 
        """
        pexpect.sendline() uses os.linesep after string, which is telnet/ssh
        client OS's line seperator, e.g. '\n' in POSIX/*nix. So we use 
        self.CRLF instead if router session, or \n for other sessions. 
        """

        if self.device_type == 'router' :
            return self.child.send(cmd + self.CRLF)
        else:
            return self.child.send(cmd + '\n')

    # ----------------------------------------------------------------------- #
    def expect(self, prompt_list='', timeout=DEFAULT_SHORT_TIMEOUT):
        """
        local expect wrapper with common exception handling
        """

        if prompt_list == '':
            prompt_list = self.prompt_list

        try: 
            return self.child.expect(prompt_list, timeout=timeout), \
                self.child.before + self.child.after

        except pexpect.EOF:
            self.print_debug_message('Received EOF', 1)

        except pexpect.TIMEOUT:
            self.print_debug_message('Session Timeout', 0)
            pys_message('expected prompt list', '\n'.join(prompt_list))

        #
        # print detailed debug 
        #
        self.print_debug_message('-----------------------------------', 2)
        self.print_debug_message('prompts : %s' % ' | '.join(prompt_list), 2)
        self.print_debug_message(str(self.child), 9)

        return -1, ''

    # ----------------------------------------------------------------------- #
    def sendline_expect(self, cmd, prompt_list='', mode='strip',
        timeout=DEFAULT_SHORT_TIMEOUT):

        """
        local expect wrapper to combine 2 pexpect procedure sendline and 
        expect with common exception handling
        """

        #
        # default, strip cmd. For some cases, like sending space to show page 
        # in IOS, then no strip
        #
        if mode == 'strip':
            cmd = cmd.strip()

        self.print_debug_message('pysession.sendline_expect(): sendline [%s]' % cmd, 
            DEBUG_MSG_VERBOSE)
        self.sendline(cmd)

        # if no given prompt_list, use the default self.prompt_list
        if prompt_list == '':
            prompt_list = self.prompt_list

        i, o = self.expect(prompt_list, timeout)

        self.print_debug_message('\n%s sendline_expect %s\n[%d]\n[%s]\n%s' % ('-'*10, 
            '-'*10, i, o, '-'*35), 3)

        return i,o

    # ----------------------------------------------------------------------- #
    def enable(self):
        """
        enter into enable mode
        """
        self.print_debug_message('\ntry to enter enable mode', 9)
    
        index, output = self.sendline_expect('enable', ['#', 'assword:'])

        #
        # no enable password, directly into enable mode
        #
        if index == 0: 
            self.print_debug_message('successfully enter enable mode', 9) 
            return 1
        #
        # receive P|password to ask for enable_password
        #
        elif index == 1: 
            index2, output = self.sendline_expect(self.enable_password, ['#']) 
                
            if index2 == 0: 
                self.print_debug_message('successfully enter enable mode', 9)
                return 1
    
        return -1

    # ----------------------------------------------------------------------- #
    def connect(self, enable_mode=1):
        """
        initial connection to router, exited after reaching enabled mode
        if enable_mode=1
        """

        #
        # spawn a session with provided connection info
        #
        self.child = pexpect.spawn(self.conn, maxread=MAX_READ)
        self.child.logfile_read = sys.stdout

        # if console, need to send a return to show the prompt
        self.sendline('\n')

        #
        # 1st send a \r\n, then check 5 possible prompts
        #
        index, o = self.sendline_expect('', 
            ['yes/no', 'sername:', 'assword:', '>', '#', '\$'])

        #pys_message('', 'EXPECT1==>%d' % index)

        #
        # child return output -> 'yes/no', asking confirmation of DSA key
        #
        if index == 0:
            self.print_debug_message('connect_0: be asked for SSH key', 2)

            index, o = self.sendline_expect('yes', 
                ['yes/no', 'sername:', 'assword:', '>', '#', '\$'])

            if index == 0:
                self.print_debug_message('connect_0: error for SSH key', 0)
                return -1
        
        #
        # child return output -> 'U|username:', providing login credentials
        #
        if index == 1:
            self.print_debug_message('connect_1: be asked for user', 2)

            index, o = self.sendline_expect(self.user, 
                ['yes/no', 'sername:', 'assword:', '>', '#', '\$'])
            
            if index < 2:
                self.print_debug_message('connect_1: error for user', 0)
                return -1
        
        #
        # child return output -> 'P|password', providing password
        #
        if index == 2:
            self.print_debug_message('pysession.connect().2: be asked for passoword',
                DEBUG_MSG_INFO)

            self.print_debug_message('pysession.connect().2: sending password [%s]' % 
                self.password, DEBUG_MSG_VERBOSE)

            index, o = self.sendline_expect(self.password, 
                ['yes/no', 'sername:', 'assword:', '>', '#', '\$'])

            if index < 3:
                self.print_debug_message('connect_2: error for password', 0)
                return -1
        
        # 
        # child return output -> '>', means login router but not into enable 
        # mode
        #
        if index == 3: 
            self.print_debug_message('connect_3: login but not enable mode',
                2)

            # prompt '>' means it is a router
            self.device_type = 'router'

            if enable_mode:
                # if conn must exit in enabled mode, go aheand for enable()
                if self.enable() == -1:
                    self.print_debug_message('connect_3: failed to enter \
                        enable mode', 2)
                    return -1

        #
        # child return output -> '#', means directly into enable mode
        #
        if index == 4: 
            self.print_debug_message('connect_4: login enable mode', 2)

            # prompt '>' means it is a router
            self.device_type = 'router'

        #
        # child return output -> '$', means it is a linux box
        #
        if index == 5: 
            self.print_debug_message('connect_5: login linux/pc', 2)

            # prompt '$' means it is a router
            self.device_type = 'pc'

        self.print_debug_message('connect: successufly login router', 1)
        
        return 1

    # ----------------------------------------------------------------------- #
    def page_off(self):
        #
        # At this time, we don't know the type of device/OS, unless 
        # it was pre-set by parameter passed thru. If self.device_os=='', we
        # send both commands
        #
        if self.device_os == '' or re.search('cisco|ios', self.device_os, re.IGNORECASE): 
            self.sendline_expect('terminal len 0')

        if self.device_os == '' or re.search('brocade|netiron', self.device_os, 
            re.IGNORECASE): 
            self.sendline_expect('skip')

    # ----------------------------------------------------------------------- #
    def parse_prompt(self):
        """
        send an empty newline, the last time of output is full prompt
        """
        i, o = self.sendline_expect('\n')

        self.prompt_line = o.split('\n')[-1].strip()

        self.prompt_list = [self.prompt_line]

        a = re.search('^([^\n]+)([#|>|\$])\s*$', self.prompt_line)

        if a:
            self.hostname, self.prompt_char = a.groups()

            if self.prompt_char == '$':
                self.prompt_char == '\\$'

            self.prompt_line = '%s[^\n]*%s' % (self.hostname, 
                self.prompt_char)

            self.prompt_list = [self.prompt_line]
        else:
            self.print_debug_message('unexpected hostname and prompt - [%s]' % \
                self.prompt_line, 1)

        self.print_debug_message('pysession.parse_prompt->promplist: %s' % 
            '|'.join(self.prompt_list), 3)

    # ----------------------------------------------------------------------- #
    def post_session(self):
        """
        1) Turn display page mode off.  
           * Cisco devices - "terminal length 0"; 
           * Brocade devices - "skip"
        2) Fetch the device prompt
        """

        if self.device_type == 'router': 
            self.page_off()

        self.parse_prompt()

    def is_session_valid(self):
        """
        parse the session info and get access(telnet|ssh|console), hostname. 
        if the session info is not valid, set accordingly. 
        """

        # parse like 'telnet 1.1.1.1' or 
        re1 = re.match('(ssh|telnet)\s+([^\s]+)', self.session)
        if re1:
            self.access=re1.group(1)
            self.hostname=re.group(2)

    def collect_sysinfo(self):
        """
        After connection established, do "show device_version" which works on most
        of network devices to collect system inforamtion, like vendor, os and
        device_version.     
        """
            
        pass

    def run_commands(self, cmds, timeout=DEFAULT_SHORT_TIMEOUT):
        output = ''

        for cmd in cmds.split('\n'):
            self.print_debug_message('\npysession.run_commands(): cmd=[%s]' % cmd, 9)

            i, _output = self.sendline_expect(cmd, timeout=timeout)
            output += _output

        self.sendline_expect('\n', timeout=timeout)

        self.print_debug_message(str(self.child), 9)

        return output

    def close(self):
        self.child.close()

# --------------------------------------------------------------------------- #
class pys_lib:
    """
    local shared library for pysession, 3 static methods:
    1) pys_pprint(list_name, list_value): 
       given 2 lists - names and values print them in a pretty way

    2) pys_message(subject, message): 
       pretty print message

    3) pys_ping_pert(output): 
       get ping success rate from router/pc

    4) psleep(seconds):
       wrappter of time.sleep(), print out '.' for each second, so 
    """ 
   
    # ----------------------------------------------------------------------- #
    @staticmethod
    def pys_pprint(list_name, list_value, action='print'): 
        str = ''
    
        max_len = len(max(list_name, key=len)) 
        
        for name, value in zip(list_name, list_value): 
            try:
                str += '%*s : [%s]\n' % (max_len, name, value) 
            except: 
                """
                for exception when print eastern characters
                """
                str += '%*s : [%s]\n' % (max_len, name, 'corruptted') 
    
        if action == 'print':
            print str
        else:
            return str
    
    # ----------------------------------------------------------------------- #
    @staticmethod
    def pys_message(subject, message):
        """
        pretty print the message, like
        /- SSSSSSSSSubject -\
        |message line 1...  |
        |message line 2...  |
        \-------------------/
        """
    
        # remove leading/tailing space on subject
        subject = subject.strip()
    
        # clear TAB in message
        message = re.sub('\t', '    ', message)
    
        # get max len of message line
        max_len = len(max(message.split('\n'), key=len))
    
        if len(subject) + 6 > max_len + 2:
            max_len = len(subject) + 6
        else:
            max_len += 2
    
        # if len is odd, change it to even
        if max_len % 2:
            max_len += 1
    
        # print the 1st line
        len_hyphen_left = (max_len - len(subject) - 4)/2
        len_hyphen_right = max_len - 4 - len(subject) - len_hyphen_left
        print '\n/', '-'*len_hyphen_left, subject, '-'*len_hyphen_right, '\\'
    
        # print message lines:
        for line in message.split('\n'):
            print '|', line, ' '*(max_len-len(line)-2), '|'
    
        # print last line
        print '\\', '-'*(max_len-2), '/'
    
    # ----------------------------------------------------------------------- #
    @staticmethod
    def pys_ping_pert(output):
        """
        parse ping command output and fetech ping pass percentage. now this
        function supports:
        1) Brocade NetIron 5.x
        2) Linux Ubunbu 14.x
        """
    
    # ----------------------------------------------------------------------- #
    #    """Brocade NetIron 5.x"""
    # ----------------------------------------------------------------------- #
    #    telnet@NIRouter#ping 1.1.1.1
    #    Sending 10, 16-byte ICMP Echo to 1.1.1.1, timeout 5000 msec, TTL 64
    #    Type Control-c to abort
    #    Reply from 1.1.1.1         : bytes=16 time<1ms TTL=64
    #    .....
    #    Success rate is 100 percent (10/10), round-trip min/avg/max=0/0/0 ms.
    #                    ^^^ =====> !!!!!!!!!!!!!!!!!
    #
    # ----------------------------------------------------------------------- #
    #    """PC/Ubuntun/14.x"""
    # ----------------------------------------------------------------------- #
    #    user@UBUNTU:~$ ping 1.1.1.1 -c 5 -i 0.5
    #    PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
    #    ....
    #    64 bytes from 1.1.1.1: icmp_seq=5 ttl=63 time=0.590 ms
    #    --- 1.1.1.1 ping statistics ---
    #    5 packets transmitted, 5 received, 0% packet loss, time 1998ms
    #                                       ^^ ===> !!!!!!!!!!!!
        pert = -1
    
        for line in output.split('\n'): 
            a = re.search('Success rate is (\d+) percent', line) 
            if a: 
                pert = int(a.group(1))
            
            b = re.search('(\d+)% packet loss', line)
            if b: 
                pert = 100- int(b.group(1))
    
        if pert == -1:
            pys_message('pys_ping_pert failed to get ping %', output)
    
        return pert 
    
    def psleep(num_sec):
        """
        pretty sleep
        """
    
        if num_sec < 0:
            return 0
    
        print '\nsleeping %d seconds:' % num_sec
        for i in range(num_sec):
            if i % 10 == 0:
                print '\nsec:%4d' % i,
            time.sleep(1)
            print '.',
            sys.stdout.flush()
        print '\n'
    
if __name__ == '__main__':
    ip = raw_input('ip address of router: ')
    cs = raw_input('console access: ')
    usr = raw_input('user: ')
    pswd = raw_input('password: ')

    cmds = """
    ! configure eth1/8 with ip and enable
    config term
    int eth 1/8
    ip address 192.168.1.1/24
    enable
    end
    """

    # -------------- test for ssh ------------- #
    _s = pysession(session='ssh -l %s %s' % (usr, ip), \
                   password=pswd, debug_level=1)
    # single cmd
    _s.run_commands('show ver')

    # multiple cmds + change prompts -> rtr(config)#
    _s.run_commands(cmds)

    # single cmd with pipeline
    _s.run_commands('show int brief wide | inc Up')

    # -------------- test for telnet ------------- #
    _t = pysession(session='telnet %s' % ip,
                   password=pswd)
    _t.run_commands('show ver')
    _t.run_commands(cmds)
    _t.run_commands('show int brief wide | inc Up')

    # -------------- test for console ------------- #
    _c = pysession(session='telnet %s' % cs, 
                   password=pswd)
    _c.CRLF = '\r\n'
    _c.run_commands('show ver')
    _c.run_commands(cmds)
    _c.run_commands('show int brief wide | inc Up')
