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
from datetime import datetime

__device_version__ = '0.1'

MAX_READ = 163840

CR = '\r'
LF = '\n'
CRLF = '\r\n'


# --------------------------------------------------------------------------- #
# CONNECT_PROMPT_LIST: for init connect() use, 
# INIT_PROMPT_LIST: for the prompt parse
# --------------------------------------------------------------------------- #
CONNECT_PROMPT_LIST = ['yes/no', 'sername:', 'assword:', '>', '#', '\$']
INIT_PROMPT_LIST =['#', '[^-]>', '\$']

# --------------------------------------------------------------------------- #
# default values, which can be changed accordingly. For example, all of 
# routers use same username and password, you don't specify it repeatedly 
# when defining session. Just change the default values
#
# DEFAULT_SHORT_TIMEOUT, pexpect uses 30 seconds. We use 10 sec instead. 
# DEFAULT_DEVICE_TYPE, given as 'router' then pysession will try to enable 
#     and page off session by sending "term len 0" and "skip"
# --------------------------------------------------------------------------- #
DEFAULT_USERNAME = ''
DEFAULT_PASSWORD = ''
DEFAULT_ENABLE_PASSWORD = ''
DEFAULT_SHORT_TIMEOUT = 60
DEFAULT_DEVICE_TYPE = 'router'

# --------------------------------------------------------------------------- #
# debug meessage level
# --------------------------------------------------------------------------- #
DEBUG_MSG_VERBOSE = 9
DEBUG_MSG_WARNING = 3
DEBUG_MSG_INFO    = 2
DEBUG_MSG_ERROR   = 1
DEBUG_MSG_CRITICAL= 0

DEFAULT_DEBUG_LEVEL = DEBUG_MSG_INFO

# --------------------------------------------------------------------------- #
class pysession:
    """
    Basic class for pysession. 

    To create a pysession to device(router, switch or server) via ssh, telnet
    or console, just create a session like:
    rtr1 = pysession(session='telnet 10.1.1.1')         ; telnet vty
    rtr2 = pysession(session='telnet 10.1.1.1 2001')    ; telnet console
    rtr3 = pysession(session='ssh -l user 10.1.1.1')    ; ssh 

    Or create a session in interactive way by giving session, user, pswd and
    enable pswd, 
    rtr1 = pysession(session='interactive')
    """

    # ----------------------------------------------------------------------- #
    def __init__(self, 
                 session='',
                 user=DEFAULT_USERNAME, 
                 password=DEFAULT_PASSWORD, 
                 enable_password=DEFAULT_ENABLE_PASSWORD, 
                 device_type=DEFAULT_DEVICE_TYPE, 
                 device_os='', 
                 device_version='', 
                 debug_level=DEFAULT_DEBUG_LEVEL):

        #
        # 1. initialize internal variables
        #
        self.prompt_line = None
        self.timeout_counter = 0
        self.timeout_max_allowed = 5

        self.device_type = device_type
        self.device_os = device_os
        self.device_version = device_version

        self.debug_dest_to_me = False
        self.EOL = CRLF

        # print each cmd in pretty line formate
        self.pprint = False

        # debug level, the higher, the more verbose, default is 0, which 
        # means none debug
        self.debug_level = debug_level

        #
        # 2. initialize session info
        #
        if session.lower() == 'interactive' or session == '':
            self.session, self.user, self.password, self.enable_password\
            = self.get_session_interactive()
        else:
            self.session, self.user, self.password, self.enable_password\
            = session, user, password, enable_password
      
        if self.debug_level: 
            print '\n'.join([self.session, self.user, self.password, \
                self.enable_password])

        # parse the session, if not valid session info, exit
        self.session_valid, self.access_mode, self.access_protocol, \
            self.hostname, _user = self.parse_session()

        self.log_file_name = 'pys__' + self.hostname + '__' + \
            datetime.now().strftime("%Y%m%d__%H:%M:%S") + '.log'

        sys.stdout = pys_logger(self.log_file_name)

        # if session is ssh, update the self.user
        if _user != '':
            self.user = _user

        #
        # prompt_list is set when session established, sth like
        # hostname_device_local[^\n]#. And this can be expanded as
        # new prompt mode, like "rconsole 1" etc
        #
        self.prompt_list = []

        # real pyexpect instance of router connection
        self.child = None

        if self.connect() == -1:
            self.print_debug_message(
                "E.pysession.__init__: unable to establish session [%s]"\
                % self.session, DEBUG_MSG_ERROR)
            self.print_debug_message(
                "E.pysession.__init__: session info -->\n%s" % self.__str__()\
                , DEBUG_MSG_ERROR)
            return 

        self.collect_sysinfo()
        
        self.post_session()

    # ----------------------------------------------------------------------- #
    def print_debug_message(self, msg, msg_level=DEBUG_MSG_VERBOSE, 
            do_repr=False):
        """
        common debug print, only print the msg with level <= self.debug_level
        """
        if self.debug_level >= msg_level:
            if do_repr:
                msg = repr(msg)
            print msg

    # ----------------------------------------------------------------------- #
    def __str__(self):
        str = '\n----------- pysession Details -----------\n'
        str += pys_lib.pys_pprint(
            ['session', 'user', 'device_type', 'device_os', \
             'device_version', 'output before', 'output after', 'EOL', \
             'access', 'log_file'],
            [self.session, self.user, self.device_type, self.device_os,\
             self.device_version,repr(self.child.before), \
             repr(self.child.after),repr(self.EOL), self.access_mode, \
             self.log_file_name],
            action="str")
        return str

    # ----------------------------------------------------------------------- #
    def get_session_interactive(self): 
        """
        if session info invalid, need to call this method to get session 
        interactivly
        """
        session = raw_input("     Please provide the session info: ")
        user    = raw_input("        User ID(press enter if none): ")
        password = \
            getpass.getpass(" Login password(press enter if none): ")
        enable_password = \
            getpass.getpass("Enable password(press enter if none): ")

        return [session, user, password, enable_password]

    # ----------------------------------------------------------------------- #
    def sendline(self, cmd): 
        """
        pexpect.sendline() uses os.linesep after string, which is telnet/ssh
        client OS's line seperator, e.g. '\n' in POSIX/*nix. So we use 
        self.EOL instead if router session, or \n for other sessions. 
        """

        cmd = cmd.strip()

        if self.device_type == 'router' :
            real_send = cmd + self.EOL
        else:
            real_send = cmd + '\n' 
        
        self.print_debug_message("L.pysession.sendline(), real_send = [%s]"\
            % repr(real_send), DEBUG_MSG_VERBOSE)

        self.print_debug_message(self.__str__(), DEBUG_MSG_VERBOSE)

        return self.child.send(real_send)

    # ----------------------------------------------------------------------- #
    def expect(self, prompt_list=[], timeout=DEFAULT_SHORT_TIMEOUT,
            looking_for_prompt=True):
        """
        local expect wrapper with common exception handling
        """

        # if not prompt_list specified, use self.prompt_list
        if prompt_list == []:
            prompt_list = self.prompt_list

        # if self.prompt_list is empty (just login no prompt collected),
        if prompt_list == []:
            prompt_list = INIT_PROMPT_LIST

        self.print_debug_message(\
            '\nL.pysession.expect.1: final prompt_list = %s'\
            % ' | '.join(prompt_list), DEBUG_MSG_VERBOSE)

        try:
            #
            # if everyting works well, return index, sum of output
            #
            return_value = self.child.expect(prompt_list, timeout=timeout)
            total_output = self.child.before + self.child.after
            self.print_debug_message(\
                '\nL.pysession.expect.2: retval=%d\nbefore:%s\nafter:%s'\
                % (return_value, self.child.before, self.child.after,), \
                DEBUG_MSG_VERBOSE)

            # reset self.timeout_counter
            self.timeout_counter = 0

            # clear child.after
            #self.child.after = ''
            #self.child.before= ''

            return return_value, total_output

        except pexpect.EOF:
            #
            # EOF: session tear down
            #
            self.print_debug_message('L.pysession.expect.2: Received EOF',\
                DEBUG_MSG_ERROR)

        except pexpect.TIMEOUT:
            #
            # Timeout: increase counter and try max_allow_timeout times
            # to get new prompt
            #
            self.print_debug_message(\
                '\nL.pysession.expect.2: TIMEOUT\nbefore:\n%s\nafter:\n%s'\
                % (self.child.before, self.child.after,), \
                DEBUG_MSG_VERBOSE)

            # increment self.timeout_counter by 1
            self.timeout_counter += 1

            # if < max_allowed, try to get prompt again if there is any
            if self.timeout_counter <= self.timeout_max_allowed and \
                looking_for_prompt:
                self.parse_prompt()
            else:
                self.print_debug_message(\
                    'E.pysession.expect(): session timeout %d times' % \
                        self.timeout_max_allowed, DEBUG_MSG_ERROR)
                self.print_debug_message(\
                    '%s E.pysession.expect(), %s %s' % ('*'*30, \
                    'prompt list', '*'*30), DEBUG_MSG_VERBOSE)
                self.print_debug_message('\n'.join(prompt_list), \
                    DEBUG_MSG_VERBOSE)
                self.print_debug_message('*'*60, DEBUG_MSG_VERBOSE)

        # print detailed debug 
        #self.print_debug_message(str(self.child), DEBUG_MSG_VERBOSE)
        self.print_debug_message(str(self.child), 0)

        return -1, ''

    # ----------------------------------------------------------------------- #
    def sendline_expect(self, send='', prompt_list=[], mode='nostrip',
        timeout=DEFAULT_SHORT_TIMEOUT):
        """
        local expect wrapper to combine 2 pexpect procedure sendline and 
        expect with common exception handling
        """

        #
        # default, strip input. For some cases, like sending space to show page 
        # in IOS, then no strip
        #
        if mode == 'strip':
            send = send.strip()

        self.print_debug_message("L.pysession.sendline_expect(), send:[%s]" \
            % repr(send), DEBUG_MSG_VERBOSE)

        self.sendline(send)

        # if no given prompt_list, use the default self.prompt_list
        if prompt_list == []:
            prompt_list = self.prompt_list

        i, o = self.expect(prompt_list, timeout)

        self.print_debug_message('\n%s L.pysession.sendline_expect %s' % \
            ('*'*20, '*'*20), DEBUG_MSG_WARNING)
        self.print_debug_message('return value: %d' % i, DEBUG_MSG_WARNING)
        self.print_debug_message('return output: \n%s' % o, DEBUG_MSG_WARNING)
        self.print_debug_message('%s' % '*'*69, DEBUG_MSG_WARNING)

        return i, o

    # ----------------------------------------------------------------------- #
    def enable(self):
        """
        enter into enable mode
        """
        self.print_debug_message(\
            '\nL.pysession.enable():try to enter enable mode', 
            DEBUG_MSG_VERBOSE)
    
        index, output = self.sendline_expect('enable', ['#', 'assword:'])

        #
        # no enable password, directly into enable mode
        #
        if index == 0: 
            self.print_debug_message(
                '\nL.pysession.enable():successfully enter enable mode', \
                DEBUG_MSG_VERBOSE) 
            return 1
        #
        # receive P|password to ask for enable_password
        #
        elif index == 1: 
            index2, output = self.sendline_expect(self.enable_password, ['#']) 
                
            if index2 == 0: 
                self.print_debug_message('successfully enter enable mode', \
                    DEBUG_MSG_VERBOSE)
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
        self.child = pexpect.spawn(self.session, maxread=MAX_READ)
        self.child.logfile_read = sys.stdout

        #
        # 1st send a \r\n, then check 5 possible prompts
        #
        self.print_debug_message(\
            'L.pysession.connect.1 - send EOL to expect return:\n%s' % \
            '_____'.join(CONNECT_PROMPT_LIST), DEBUG_MSG_VERBOSE)

        index, o = self.sendline_expect(send=self.EOL, 
            prompt_list=CONNECT_PROMPT_LIST)

        self.print_debug_message(\
            'L.pysession.connect.2 - get indexed return %d' % index, \
            DEBUG_MSG_VERBOSE)
        #
        # child return output -> 'yes/no', asking confirmation of DSA key
        #
        if index == 0:
            self.print_debug_message('connect_0: be asked for SSH key', 2)

            index, o = self.sendline_expect('yes',
                prompt_list=CONNECT_PROMPT_LIST)

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
            self.print_debug_message(\
                'I.pysession.connect.2: being asked for passoword',
                DEBUG_MSG_INFO)

            index, o = self.sendline_expect(self.password, 
                prompt_list=CONNECT_PROMPT_LIST)

            if index < 3:
                self.print_debug_message(\
                'E.I.pysession.connect.2: password error', DEBUG_MSG_ERROR)
                return -1
        
        # 
        # child return output -> '>', means login router but not into enable 
        # mode
        #
        if index == 3: 
            self.print_debug_message(
                'I.pysession.connect.3: login none-enable mode', 
                DEBUG_MSG_INFO)

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

        self.parse_prompt()

        self.print_debug_message(\
            'L.pysession.connect(): successfully login router', \
            DEBUG_MSG_ERROR)
        
        return 1

    # ----------------------------------------------------------------------- #
    def page_off(self):
        #
        # At this time, we don't know the type of device/OS, unless 
        # it was pre-set by parameter passed thru. If self.device_os=='', we
        # send both commands
        #
        if self.device_os == '' or re.search('cisco|ios', self.device_os, 
            re.IGNORECASE): 
            self.sendline_expect('terminal len 0')

        if self.device_os == '' or re.search('brocade|netiron', self.device_os, 
            re.IGNORECASE): 
            self.sendline_expect('skip')

    # ----------------------------------------------------------------------- #
    def parse_prompt(self, send_EOL=True):
        """
        send an empty newline, the last time of output is full prompt, 
        """

        #keep_debug_level = self.debug_level; self.debug_level = 10

        #
        # parse_prompt.1: send an EOL
        #
        if send_EOL: 
            self.child.send(self.EOL) 
            self.print_debug_message(
                'L.pysession.parse_prompt.1: send an EOL', DEBUG_MSG_VERBOSE)
        else:
            self.print_debug_message(
                'L.pysession.parse_prompt.1: no EOL send', DEBUG_MSG_VERBOSE)

        #
        # parse_prompt.2: expect one of INIT_PROMPT_LIST #|>|$
        #
        i, o = self.expect(prompt_list=INIT_PROMPT_LIST, \
            looking_for_prompt=False)
        self.print_debug_message('L.pysession.parse_protmp.2: rcv index %d'\
            % i, DEBUG_MSG_VERBOSE)

        #
        # parse_prompt.3: parse the last line to get prompt
        #
        prompt_line = o.split('\n')[-1].strip()

        # looking for 'telnet@hostname_gw_newyork#' or 'LP-1>'
        # host        -> 'telnet@hostname_gw_newyork'
        # prompt_char -> '#'
        #
        # Avoid Invalid input -> Enable
        #
        re_prompt_found = re.search('^([^\n]+[^-])([#|>|\$])$', prompt_line)

        if re_prompt_found:
            host, prompt_char = re_prompt_found.groups()

            # Brocade NetIron: take out telnet|ssh if any from host
            if '@' in host:
                host = host.split('@')[1]

            if prompt_char == r'$':
                prompt_char == '\\$'

            this_prompt = '%s[^\n]*%s' % (host, prompt_char)

            self.print_debug_message(\
                'L.pysession.parse_prompt: get prompt - [%s]' % \
                repr(this_prompt), DEBUG_MSG_VERBOSE)

            #if this_prompt not in self.prompt_list:
            #    self.prompt_list.append(this_prompt)
            self.prompt_list=[this_prompt]

        else:
            self.print_debug_message(\
                'E.pysession.parse_prompt: unexpected hostname/prompt - [%s]'\
                % self.prompt_line, DEBUG_MSG_ERROR)

        self.print_debug_message(\
                'D.pysession.parse_prompt: promplist: %s'\
                    % '|'.join(map(repr, map(repr,self.prompt_list))), 
                DEBUG_MSG_WARNING)

        #self.debug_level = keep_debug_level

        return o
    # ----------------------------------------------------------------------- #
    def post_session(self):
        """
        1) Turn display page mode off.  
           * Cisco devices - "terminal length 0"; 
           * Brocade devices - "skip"
        2) Fetch the device prompt
        """

        if self.device_type == 'router' or self.device_type == 'switch':
            self.page_off()

        #self.parse_prompt()

    # ----------------------------------------------------------------------- #
    def parse_session(self):
        """
        parse the session info and get access info. 

        input:
        ======
        * telnet  1.2.3.4
        * ssh     -l user hostname.location.com
        * telnet  ts1.company.com 2001

        output:
        =======
        0) valid session: True|False
        1) access_mode:   telnet|ssh|console
        2) protocol:      telnet|ssh
        3) hostname:      a.b.c.d or <hostname> or term_svr:port#
        4) user:          only for ssh session
        """

        # remove leading and tailing spaces
        self.session = self.session.strip()

        # 'telnet  1.2.3.4' or 'telnet hostname.company.com'
        re_telnet_found = re.search('^telnet\s+(\S+)$', self.session)
        if re_telnet_found:
            return True, 'telnet', 'telnet', re_telnet_found.group(1), ''

        re_ssh_found = re.search('^ssh\s+-l\s+(\S+)\s+(\S+)$', self.session)
        if re_telnet_found:
            return True, 'ssh', 'ssh', re_ssh_found.group(2), re_ssh_found(1)

        re_console_found = re.search('^telnet\s+(\S+)\s+(\d+)$', self.session)
        if re_console_found:
            return True, 'console', 'telnet', \
                ':'.join(re_console_found.groups()), ''
     
        return False, '', '', '', ''

    # ----------------------------------------------------------------------- #
    def set_debug_dest_to_me(self):
        if self.debug_dest_to_me:
            return
        
        self.debug_dest_to_me = True

        output = self.send('show who')

        session = ''
        session_num = ''

        for line in output.split('\n'):
            # search for (Console|Telnet|SSH) connections
            re_conn = re.match('^(Console|Telnet|SSH) connections', line)
            if re_conn: 
                session = re_conn.group(1)
                        
            # search for  [ 1      established,.*]
            re_conn_num = re.match('^\s+(\d+)\s+established,', line)
            if re_conn_num:
                session_num = re_conn_num.group(1)


            # search for         you are connecting to this session
            re_you_conn = re.match('^\s+you are connecting to this session', line)
            if re_you_conn:
                break

        self.send('debug destination %s %s' % (session, session_num))
        
    # ----------------------------------------------------------------------- #
    def collect_sysinfo(self):
        """
        After connection established, do "show device_version" which works on
        most of network devices to collect system inforamtion, like vendor, os
        and device_version. 

        Under construction !!!!
        """
        pass

    # ----------------------------------------------------------------------- #
    def cmd_change_prompt(self, cmd=''):
        cmd = cmd.strip().lower()

        # rc 1, rconsole 10, etc, change the prompt
        if re.match('^rc.*\s\d+', cmd):
            return True

        # exit
        if re.match('^ex.*', cmd):
            return True

        # enable
        if re.match('^en.*', cmd):
            return True

        return False

    # ----------------------------------------------------------------------- #
    def send_line(self, line='', timeout=DEFAULT_SHORT_TIMEOUT):
        '''
        send one line 
        1) if this cmd is expected to change prompt; do
           * send cmd+EOL
           * parse new prompt
           * return combined output
        2) if not change prompt, just simply sendline_expect

        The difference vs sendline, from here the return value is output only
        not (index, output)
        '''
        line = line.strip()

        if self.pprint: 
            print '\n' + pys_lib.pline1('!!!CMD:%s!!!' % line)

        if self.cmd_change_prompt(cmd=line): 

            self.print_debug_message(\
                'L.pysession.send_line.1: line=[%s], expecting prompt change'\
                    % line, DEBUG_MSG_VERBOSE)

            #self.child.send(line + self.EOL) 
            self.child.send(line)
            _output = self.parse_prompt()

        else: 
            if re.search('^deb', line.strip()):
                self.set_debug_dest_to_me()

            i, _output = self.sendline_expect(send=line, timeout=timeout)

        return _output

    # ----------------------------------------------------------------------- #
    def send(self, lines='', timeout=DEFAULT_SHORT_TIMEOUT):
        '''
        transmit lines to device. can be single line or multiple lines
        like:
        single line of cmd
        --------------------------------
        router.transmit("show ver")
        --------------------------------

        or multiple line of cmd
        --------------------------------
        router.transmit("""
            conf term
            inter ve 1
            ip address 1.1.1.1/24
            """)
        --------------------------------
        '''
        output = ''
        line_counter = 1

        for line in lines.split('\n'):
            line_counter += 1
            self.print_debug_message(\
                'L.pysession.transmit.1: #%02d line=[%s]' % 
                (line_counter, line), DEBUG_MSG_VERBOSE)

            _output = self.send_line(line=line, timeout=timeout)
            output += _output

        #self.sendline_expect(send='\n', timeout=timeout)
        #self.print_debug_message(str(self.child), DEBUG_MSG_VERBOSE)

        return output

    # ----------------------------------------------------------------------- #
    def close(self):
        self.child.close()

# --------------------------------------------------------------------------- #
class pys_logger:
    """
    local logger module, with this we can output to 2 stdout and pysession
    log file
    """
    def __init__(self, log_file_name="pys_log_file"):
        self.terminal = sys.stdout
        self.log = open(log_file_name, 'a')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

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
    
    # ----------------------------------------------------------------------- #
    @staticmethod
    def psleep(num_sec, reason=''):
        """
        pretty sleep
        """
    
        if num_sec < 0:
            return 0
    
        print pys_lib.pline2('sleeping %d seconds: %s' % (num_sec, reason))
        for i in range(num_sec):
            if i % 10 == 0:
                print 'sec:%4d' % i,
            time.sleep(1)
            print '.',
            sys.stdout.flush()

            if i % 10 == 9:
                print '\n',
        print pys_lib.pline2('\n END of sleeping %d seconds ' % num_sec)
    
    # ----------------------------------------------------------------------- #
    @staticmethod
    def pline1(line): 
        """
        pline1 - pretty line 1
        >>>>>>>>>>>>>>>>>>>>>>>>> LINE <<<<<<<<<<<<<<<<<<<<<<<< 
        """
        l = len(line) 
        ll= (76-l)/2 
        return '%s  %s  %s' % ('>'*ll, line, '<'*(76-l-ll))

    # ----------------------------------------------------------------------- #
    @staticmethod
    def pline2(line): 
        """
        pline2 - pretty line 2
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        !                    LINE                        !
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        """
        l = len(line) 
        ll= (78-l)/2 
        return '\n%s\n!%s%s%s\n%s' % ('!'*80, ' '*ll, line, ' '*(78-l-ll), '!'*80)

if __name__ == '__main__':
    #rtr = pysession(session='interactive')
    #rtr = pysession(session='telnet 10.18.24.78')
    rtr = pysession(session='telnet 10.31.168.16 3001')
    
    rtr.pprint = True

    print '\n', '!' * 20, ' end of session establishment ', '!' * 20 
    while True:
        input = raw_input('\ninput command (^C to exit): ')

        print '!' * 10, input, '!' * 10 

        o = rtr.send(lines=input)

        print '\n', '+' * 35, 'OUTPUT', '+' * 35
        print o
        print '=' * 80

