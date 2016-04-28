#!/usr/bin/env python

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
import os
import sys
import time
import getopt
import getpass
import pexpect
from datetime import datetime

__version__ = '1.0'


# --------------------------------------------------------------------------- #
# Default Values
# --------------------------------------------------------------------------- #
'''
We have 3 tiers of value assignment and later ones overwrite the previous
1) hard-coded in pysession.py as below
2) defined in pysession.conf
3) send in as argument when calling pysession()
'''

# EOL values: CR, LF and CRLF
CR   = '\r'
LF   = '\n'
CRLF = '\r\n'

CONF_FILENAME   = './pysession.conf'
MUST_ENABLE     = True
LOG_FILE_PREFIX = 'pys__'
MAX_READ        = 327680
SHORT_TIMEOUT   = 15
LONG_TIMEOUT    = 120
TERM_WIDTH      = 112

# --------------------------------------------------------------------------- #
# debug meessage level
# --------------------------------------------------------------------------- #
DEBUG_MSG_VERBOSE = 9
DEBUG_MSG_WARNING = 3
DEBUG_MSG_INFO    = 2
DEBUG_MSG_ERROR   = 1
DEBUG_MSG_CRITICAL= 0
DEBUG_LEVEL = 0


# --------------------------------------------------------------------------- #
class pysession:
    """
    Basic class for pysession. 

    To create a pysession to device(router, switch or server) via ssh, telnet
    or console, just create a session like:
    rtr1 = pysession(session='telnet 10.1.1.1')      ; telnet vty
    rtr2 = pysession(session='telnet 10.1.1.1 2001') ; telnet console
    rtr3 = pysession(session='ssh -l user 10.1.1.1') ; ssh 
    rtr3 = pysession(session='ssh user@10.1.1.1')    ; ssh 

    Or create a session in interactive way by giving session, user, pswd and
    enable pswd, 
    rtr1 = pysession(session='interactive')
    """

    # ----------------------------------------------------------------------- #
    def __init__(self, 
                 jump_session='',
                 jump_user='',
                 jump_password='',
                 session='',
                 user='', 
                 password='',
                 enable_password='',
                 \
                 output_file='', 
                 log_file_prefix='', 
                 timeout=None,
                 debug_level=None, 
                 conf_file=CONF_FILENAME,
                 ):

        #
        # 0. lists of possible prompt and corresponding actions
        # 

        # prompt|action_all_list, used for jump/login/session stages
        self.prompt_list_all_stages = []
        self.action_list_all_stages = []

        # prompt|action_login_list, used for jump/login stages
        self.prompt_list_login = []
        self.action_list_login = []

        # prompt|action_login_list, used for jump/login stages
        self.prompt_list_jump = []
        self.action_list_jump = []

        # prompt|action_login_console_list, used for jump/login stages
        self.prompt_list_login_console = []
        self.action_list_login_console = []

        # prompt|action_enable_list, used for prompt parse
        self.prompt_enable_list = []
        self.action_enable_list = []

        # special commands and handling list
        self.command_special_list = []
        self.handling_special_list = []

        # list of prompt/action used by expect()
        self.stage = 'init'
        self.prompt_list = []
        self.action_list = []
        self.current_prompt = ''
        self.first_time_timeout = True

        self.debug_level = DEBUG_LEVEL

        #
        # 1. read conf file and update default values + prompt list
        #
        self.read_conf_file(conf_file)
        
        #
        # 2. initialize internal variables
        #
        if timeout: 
            self.timeout = timeout
        else:
            self.timeout = SHORT_TIMEOUT

        self.timeout_counter = 0
        self.login_timeout_counter = 0
        self.timeout_max_allowed = 5

        # for Brocade NI/FI platform, set debug destination to current session
        self.debug_dest_to_me = False

        # EOL - End of Line, Default is CR(\r)
        self.EOL = CR

        # log format: 
        # ----- 2016-04-15, 17:09, ssh admin@172.16.1.1 -----
        # +++++++++++++++++++++++++++++++++++++++++++++++++++
        self.log_format = 'Date_Time_Session_Command'

        # internal counters of commands and timer
        self.counter_line = 0
        self.counter_command = 0
        self.counter_invalid_command = 0
        self.start_time = time.time()
        self.sleep_time = 0

        # session must go to enable mode, if False, login at > then leave
        self.must_enable = MUST_ENABLE

        # session log file prefix
        if log_file_prefix == '':
            log_file_prefix = LOG_FILE_PREFIX

        # debug level, the higher, the more verbose, default is 0, which 
        # means none debug
        if debug_level == None: 
            self.debug_level = DEBUG_LEVEL
        else:
            self.debug_level = debug_level

        #
        # 4. initialize session info
        #
        if session.lower() == 'interactive':
            self.session, self.user, self.password, self.enable_password\
            = self.get_session_interactive()
        elif session.lower() == 'juminteractive':
            self.jump_session, self.jump_user, self.jump_password,\
            self.session, self.user, self.password, self.enable_password\
            = self.get_session_jump_interactive()
        else:
            self.jump_session, self.jump_user, self.jump_password,\
            self.session, self.user, self.password, self.enable_password\
            = jump_session, jump_user, jump_password, session, user,\
            password, enable_password
      
        # parse the session, if not valid session info, exit
        self.session_valid, self.session_protocol, self.hostname, ssh_user = \
            self.parse_session()

        # if session is ssh, update the self.user
        if ssh_user != '':
            self.user = ssh_user

        # if ssh, self.EOL='\n'
        #if self.session_protocol == 'ssh': self.EOL = LF

        # create log_file_name
        self.log_file_name = output_file
        if self.log_file_name == '': 
            self.log_file_name = log_file_prefix + self.hostname + '__' + \
                datetime.now().strftime("%Y%m%d__%H:%M:%S") + '.log'

        sys.stdout = PYSLogger(self.log_file_name)

        # real pyexpect instance of router connection
        self.child = None

        if self.jump_login() == -1:
            self.print_debug_message(
                "E.pysession.__init__: unable to establish session [%s]"\
                % self.session, DEBUG_MSG_CRITICAL)
            self.print_debug_message(
                "E.pysession.__init__: session info -->\n%s" % self.__str__()\
                , DEBUG_MSG_ERROR)
            return 

    # ----------------------------------------------------------------------- #
    def read_conf_file(self, conf_file_name):
        '''
        read conf file to fetch default values, prompt/action, 
        command/handling info. In this way, no need to hard code every
        possible prompts in py file, but user can define themselves. 
        '''
        global MUST_ENABLE, LOG_FILE_PREFIX, DEBUG_LEVEL, MAX_READ, \
            SHORT_TIMEOUT, LONG_TIMEOUT

        conf = PYSConfigParser()
        conf.read(conf_file_name)

        #
        # loop to parse every section, reporting unknown/unsupported ones
        #
        for s in conf.sections:
            # defaul values
            if s == 'DefaultValues':
                for k,v in conf.dict['DefaultValues'].iteritems():
                    if k == 'MustEnable':
                        MUST_ENABLE = (v.lower()=='true')
                    elif k == 'LogFilePrefix':
                        LOG_FILE_PREFIX = v
                    elif k == 'DebugLevel':
                        DEBUG_LEVEL = int(v)
                    elif k == 'MaxRead':
                        MAX_READ = int(v)
                    elif k == 'ShortTimeout':
                        SHORT_TIMEOUT = int(v)
                    elif k == 'LongTimeout':
                        LONG_TIMEOUT = int(v)
                    else:
                        print 'E.pysession.read_conf_file(): unsupported %s, %s'\
                            % (k, v)
    
            # prompt|action_list for all stages: jump|login|session|enable
            elif s == 'Prompt.Stage.All':
                for k,v in conf.dict['Prompt.Stage.All'].iteritems():
                    self.prompt_list_all_stages.append(k)
                    self.action_list_all_stages.append(v)
   
            # prompt|action_list for login stage
            elif s == 'Prompt.Stage.Login':
                for k,v in conf.dict['Prompt.Stage.Login'].iteritems():
                    self.prompt_list_login.append(k)
                    self.action_list_login.append(v)
    
            # prompt|action_list for login/console stage
            #
            # special one, existing console may stays at MP OS, LP console, or
            # enable mode, send exit to return enable mode
            elif s == 'Prompt.Stage.Login.Console':
                for k,v in conf.dict['Prompt.Stage.Login.Console'].iteritems():
                    self.prompt_list_login_console.append(k)
                    self.action_list_login_console.append(v)
    
            # prompt|action_list for jump stage
            elif s == 'Prompt.Stage.Jump':
                for k,v in conf.dict['Prompt.Stage.Jump'].iteritems():
                    self.prompt_list_jump.append(k)
                    self.action_list_jump.append(v)
    
            # prompt|action_list for enable stage
            elif s == 'Prompt.Stage.Enable':
                for k,v in conf.dict['Prompt.Stage.Enable'].iteritems():
                    self.prompt_enable_list.append(k)
                    self.action_enable_list.append(v)
    
            # command|handling_list for special commands, see .conf file
            elif s == 'Command.Special':
                for k,v in conf.dict['Command.Special'].iteritems():
                    self.command_special_list.append(k)
                    self.handling_special_list.append(v)

            # unknown/unsupport sections
            else:
                self.print_debug_message( 
                    msg='\nE.expect(): unknown sections - %s\n' % s, 
                    msg_level=DEBUG_MSG_ERROR)
                
    # ----------------------------------------------------------------------- #
    def print_debug_message(self, msg='', msg_level=DEBUG_MSG_VERBOSE, 
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
        str += PYSLib.pys_pprint(
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
    def get_info_or_interactive(self, v, msg='Please provide info:', 
        is_pswd=True): 
        """
        get information, if null, start to collect interactively
        """
        if v == '':
            if is_pswd:
                v = getpass.getpass(msg)
            else: 
                v = raw_input(msg)

        return v

    # ----------------------------------------------------------------------- #
    def get_session_interactive(self): 
        """
        if session info = 'interactive', call this method to get session 
        interactivly
        """
        session = \
            raw_input(      "     Please provide the session info: ")
        user    = \
            raw_input(      "        User ID(press enter if none): ")
        password = \
            getpass.getpass(" Login password(press enter if none): ")
        enable_password = \
            getpass.getpass("Enable password(press enter if none): ")

        return [session, user, password, enable_password]

    # ----------------------------------------------------------------------- #
    def get_jump_session_interactive(self): 
        """
        if session info = 'jumpinteractive', call this method to get session 
        interactivly
        """
        jump_session  = \
            raw_input(      "    Please provide the jump session info: ")
        jump_user     = \
            raw_input(      "       User jump ID(press enter if none): ")
        jump_password = \
            getpass.getpass("Login jump password(press enter if none): ")
        session = raw_input("         Please provide the session info: ")
        user    = raw_input("            User ID(press enter if none): ")
        password = \
            getpass.getpass("     Login password(press enter if none): ")
        enable_password = \
            getpass.getpass("    Enable password(press enter if none): ")

        return [session, user, password, enable_password]

    # ----------------------------------------------------------------------- #
    def expect(self, prompt_list=[], action_list=[], timeout=0, 
        looking_for_prompt=True):
        """
        local expect wrapper with common exception handling
        """
        if timeout == 0:
            timeout = self.timeout

        # if empty prompt_list, use self.prompt_list. This is for prompt parse
        if len(prompt_list) == 0:
            prompt_list = self.prompt_list
            action_list = self.action_list
        
        output = ''

        # 
        # To exit this for-ever expect loop: 
        # 1) action_list[r]==$done; 
        # 2) pexpect.EOF; 
        # 3) pexpect.Timeout
        #
        while True:
            # print out expected prompts 
            self.print_debug_message(\
                msg='\n%s  L.expect(): prompts vs action  %s\n%s' % (
                    '-' * 25, 
                    '-' * 25,
                    PYSLib.pys_pprint(
                        map(repr,self.prompt_list), 
                        action_list, 
                        action="str"
                        ),
                    ),
                msg_level=DEBUG_MSG_VERBOSE
                )
                
            try: 
                r = self.child.expect(prompt_list, timeout=timeout) 
    
                self.print_debug_message(
                    msg='\nL.expect(): ---> %d/%s : %s' % (
                        r, 
                        repr(prompt_list[r]), 
                        action_list[r]
                        ),
                    msg_level=DEBUG_MSG_VERBOSE, 
                    )
                
                output += self.child.before + self.child.after 
    
                if action_list[r] == '$done' or \
                    action_list[r] == '$user' or \
                    action_list[r] == '$enable' or \
                    action_list[r] == '$password':
                    ''' $done prompt gotten, reset counter and return '''

                    # reset self.timeout_counter
                    self.timeout_counter = 0
        
                    # clear child.after
                    self.child.after = '' 
                    self.child.before= ''
        
                    return r, output 

                elif action_list[r] == '$space':
                    ''' if return $space, it is a page break, sending space''' 
                    self.print_debug_message(
                        msg='\nL.pysession.expect: page break', 
                        msg_level=DEBUG_MSG_VERBOSE,
                        )
                    self.child.send(' ') 
                else:    
                    '''else means unknown action, send $action,YG'''

                    self.print_debug_message(
                        msg='\nL.pysession.expect: sending %s' % action_list[r], 
                        msg_level=DEBUG_MSG_VERBOSE,
                        )
                    if action_list[r][-1] == '$': 
                        self.child.send(self.action_list[r][:-1]) 
                    else: 
                        self.child.send(self.action_list[r] + self.EOL)

            except pexpect.EOF:
                #
                # EOF: session tear down
                #
                self.print_debug_message('L.pysession.expect.2: Received EOF',\
                    DEBUG_MSG_ERROR)

                return pexpect.EOF, output
    
            except pexpect.TIMEOUT:
                #
                # If first_time_timeout, don't parse promt but return TIMEOUT
                # 
                # Only for jump_login(), console connection for some vendor 
                # boxes, need to send an additional return in jump_login()
                #
                # otherwise parse_prompt if timeout for first 3 times. 
                #
                if self.stage == 'login' or self.stage == 'jump': 
                    return pexpect.TIMEOUT, output
                #    self.login_timeout_counter += 1
                #    if self.login_timeout_counter == 1:
                #        self.print_debug_message(
                #            'L.expect(): send "n" bcoz 1st timeout', 
                #            DEBUG_MSG_ERROR)
                # 
                #        self.child.send('n')
                #        return pexpect.TIMEOUT, output
                # 
                #    elif self.login_timeout_counter == 2:
                #        self.print_debug_message(
                #            'L.expect(): send EOL bcoz 2st timeout', 
                #            DEBUG_MSG_ERROR)
                # 
                #        self.child.send(self.EOL) 
                #        return pexpect.TIMEOUT, output

                #
                # Timeout: increase counter and try max_allow_timeout times
                # to get new prompt
                #
                if looking_for_prompt:
                    self.child.sendcontrol('c') 
                    #self.child.send(self.EOL) 

                    # increment self.timeout_counter by 1
                    self.timeout_counter += 1
    
                    self.print_debug_message(
                        '\nL.expect(): TIMEOUT %d times\nbefore:\n%s\nafter:\n%s'\
                        % (self.timeout_counter, self.child.before, \
                        self.child.after,), DEBUG_MSG_VERBOSE)
        
                    # if < max_allowed, try to get prompt again if there is any
                    if self.timeout_counter <= self.timeout_max_allowed:
                        output += self.parse_prompt() 
                        self.make_prompt_action_list()
                    else: 
                        return pexpect.TIMEOUT, output
                else: 
                    return pexpect.TIMEOUT, output
        # print detailed debug 
        # self.print_debug_message(str(self.child), 0)
        return -1, ''
    
    # ----------------------------------------------------------------------- #
    def get_user(self):
        """
        get user id depend on stage
        """
        if self.stage == 'jump':
            return self.get_info_or_interactive(self.jump_user, \
                msg="Please provide jump user id: ", is_pswd=False)
        else:
            return self.get_info_or_interactive(self.user, \
                msg="Please provide user id: ", is_pswd=False)
    
    # ----------------------------------------------------------------------- #
    def get_password(self):
        """
        get user password depend on stage
        """
        if self.stage == 'jump':
            return self.get_info_or_interactive(self.jump_password, \
                msg="Please provide jump user password: ", is_pswd=True)
        elif self.stage == 'login':
            return self.get_info_or_interactive(self.password, \
                msg="Please provide login password: ", is_pswd=True)
        else:
            return self.get_info_or_interactive(self.enable_password, \
                msg="Please provide enable password: ", is_pswd=True)

    # ----------------------------------------------------------------------- #
    def make_prompt_action_list(self):
        '''
        construct prompt|action list
        '''

        self.prompt_list = self.prompt_list_all_stages[:]
        self.action_list = self.action_list_all_stages[:]

        if self.stage == 'jump': 
            self.prompt_list += self.prompt_list_jump 
            self.action_list += self.action_list_jump

        elif self.stage == 'login' or self.stage == 'enable':
            self.prompt_list += self.prompt_list_login 
            self.action_list += self.action_list_login

            if self.session_protocol == 'console': 
                self.prompt_list += self.prompt_list_login_console 
                self.action_list += self.action_list_login_console

        elif self.stage == 'done': 
            self.prompt_list.append(self.current_prompt)
            self.action_list.append('$done')

        else:
            self.print_debug_message(
                'E.make_prompt_action_list: unknown stage [%s]'
                % self.stage, DEBUG_MSG_ERROR)
            
    # ----------------------------------------------------------------------- #
    def jump_login(self):
        """
        establish connection to device, 1) jump then login; 2) or login
        """

        #
        # spawn a connection either jump or session
        #
        if self.jump_session != '': 
            self.child = pexpect.spawn(self.jump_session, maxread=MAX_READ)
            self.stage = 'jump'
        else:
            self.child = pexpect.spawn(self.session, maxread=MAX_READ)
            self.stage = 'login'

        self.child.logfile_read = sys.stdout

        # construct prompt|action list
        self.make_prompt_action_list()

        while True: 
            # during jump_login process, using 5 sec as timeout value since
            # all commands here are small ones
            r, o = self.expect(timeout=5)

            # if return pexpect.TIMEOUT, just send a \r
            if r == pexpect.TIMEOUT:
                if self.timeout_counter > self.timeout_max_allowed: 
                    self.print_debug_message( 
                        '\nE.jump_login(): timeout, exiting...', 
                        DEBUG_MSG_CRITICAL)
                    sys.exit(1) 
                else:
                    self.timeout_counter += 1
                    self.child.sendcontrol('c')
                    continue
            elif r == pexpect.EOF or (type(r) is int and r == -1):
                self.print_debug_message(
                    '\nE.jump_login(): critical error, exiting...', 
                    DEBUG_MSG_CRITICAL)
                sys.exit(1) 
                
            # print out debug msg
            #_action_list = self.action_list[:]
            #
            #if type(r) == int and r < len(_action_list): 
            #    _action_list[r] = '--->  ' + _action_list[r] 

            #self.print_debug_message(\
            #    msg='\n%s  L.connect: prompts vs action  %s\n%s' % (
            #        '-' * 25, 
            #        '-' * 25,
            #        PYSLib.pys_pprint(
            #            map(repr,self.prompt_list), 
            #            _action_list,
            #            action="str"),
            #        ),
            #    msg_level=DEBUG_MSG_VERBOSE
            #    )
            
            if self.action_list[r] == '$done':
                if self.stage == 'jump':
                    self.child.send(self.session + self.EOL)
                    self.stage = 'login'
                else:    
                    break
            elif self.action_list[r] == '$user': 
                self.child.send(self.get_user() + self.EOL)
            elif self.action_list[r] == '$password':
                self.child.send(self.get_password() + self.EOL)
            elif self.action_list[r] == '$enable': 
                self.stage = 'enable'
                self.child.send('enable' + self.EOL)
            else:
                self.print_debug_message(\
                    msg='\nE.connect: unknown action, %d/%s' % \
                        (r, self.action_list[r]), 
                    msg_level=DEBUG_MSG_ERROR
                    )

            #elif self.action_list[r] == '$space':
            #    self.child.send(' ')
            #else:
            #    if self.action_list[r][-1] == '$':
            #        self.child.send(self.action_list[r][:-1])
            #    else:
            #        self.child.send(self.action_list[r] + self.EOL)

        self.parse_prompt()

        self.stage = 'done'
        self.make_prompt_action_list()

        self.print_debug_message(\
            msg='\n%s  L.connect: after prompt parse  %s\n%s' % (
                '-' * 25, 
                '-' * 25, 
                PYSLib.pys_pprint( 
                    map(repr,self.prompt_list), 
                    self.action_list, 
                    action="str"
                    )
                ),
                msg_level=DEBUG_MSG_VERBOSE
                )
            
        self.sendline_expect('terminal len 0')
        self.sendline_expect('skip')

        return 1

    # ----------------------------------------------------------------------- #
    def parse_prompt(self, send_EOL=True):
        """
        parse the prompt to get exact hostname, the prompt will be
        hostname[^\n]#, for example telnet@LA.Gateway(config-if-e10000-1/5)#
        the prompt line "LA.Gateway[^\n]#". So when script goes into configure
        mode, will not miss the prompt
        """
        # parse_prompt.1: send an EOL
        if send_EOL:
            self.child.send(self.EOL) 

        # parse_prompt.2: expect one of self.prompt_enable_list
        r, o = self.expect(
            prompt_list=self.prompt_enable_list, 
            action_list=self.action_enable_list,
            )

        # parse_prompt.3: parse the last non-empty line to get prompt
        prompt_line = ''
        for l in reversed(o.split('\n')):
            prompt_line = l.strip()
            if len(prompt_line):
                break 

        self.print_debug_message(\
            '\nL.parse_prompt(): prompt line=[%s]' % prompt_line, 
            DEBUG_MSG_VERBOSE
            )

        #
        # looking for config prompt 'telnet@hostname(config-if-e10000-1/5)#'
        #
        re_prompt_config = re.search('^([^\n]+)\((.*)\)([#|>|\$])$', \
            prompt_line)

        #
        # looking for 'telnet@hostname_gw_newyork#' or 'LP-1>'
        #
        #re_prompt_simple = re.search('^([^\n]+[^-])([#|>|\$])$',\
        re_prompt_simple = re.search('^([^\n]+[^-])([#|>|\$])$',\
            prompt_line)

        if re_prompt_config:
            host, config, prompt_char = re_prompt_config.groups()

            # Brocade NetIron: take out telnet|ssh if any from host
            if '@' in host:
                host = host.split('@')[1]

            if prompt_char == r'$':
                prompt_char == '\\$'

        elif re_prompt_simple:
            host, prompt_char = re_prompt_simple.groups()

            # Brocade NetIron: take out telnet|ssh if any from host
            if '@' in host:
                host = host.split('@')[1]

            if prompt_char == r'$':
                prompt_char == '\\$'

        else:
            self.print_debug_message(\
                'E.parse_prompt: unexpected hostname/prompt - [%s]'\
                % prompt_line, DEBUG_MSG_ERROR)
            
            host = prompt_line
            prompt_char = ''
        
        self.current_prompt = '%s[^\n]*%s' % (host, prompt_char) 
        
        self.print_debug_message(\
            'L.parse_prompt: current prompt = [%s]' % \
            repr(self.current_prompt), DEBUG_MSG_VERBOSE
            )

        return o
    
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
        1) protocol:      telnet|ssh
        2) hostname:      a.b.c.d or <hostname> or term_svr:port#
        3) user:          only for ssh session
        """

        # remove leading and tailing spaces
        self.session = self.session.strip()

        # 'telnet  1.2.3.4' or 'telnet hostname.company.com'
        re_telnet_found = re.search('^telnet\s+(\S+)$', self.session)
        if re_telnet_found:
            return True, 'telnet', re_telnet_found.group(1), ''

        # 'ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -l admin 10.17.146.21'
        re_ssh_found1 = re.search('^ssh\s+.*-l\s+(\S+)\s+(\S+)$', self.session)
        if re_ssh_found1:
            return True, 'ssh', re_ssh_found1.group(2), \
                re_ssh_found1.group(1)

        # 'ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 admin@10.17.146.21'
        re_ssh_found2 = re.search('^ssh\s+.*\s+(\S+)@(\S+)$', self.session)
        if re_ssh_found2:
            return True, 'ssh', re_ssh_found2.group(2), \
                re_ssh_found2.group(1)

        re_console_found = re.search('^telnet\s+(\S+)\s+(\d+)$', self.session)
        if re_console_found:
            return True, 'console', \
                ':'.join(re_console_found.groups()), ''
     
        return False, '', '', ''

    # ----------------------------------------------------------------------- #
    def set_debug_dest_to_me(self):
        '''
        For Brocade NetIron product, you need to set debug destination to 
        current session. 
        '''
        if self.debug_dest_to_me:
            return
        
        self.debug_dest_to_me = True

        output = self.send_line('show who')

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

        self.send_line('debug destination %s %s' % (session, session_num))
        
    # ----------------------------------------------------------------------- #
    def is_command(self, cmd='', type='$changeprompt'):
        '''
        search self.command_special_list one by one to see if cmd==type
        '''
        cmd = cmd.strip().lower()

        for c, h in zip(self.command_special_list, 
            self.handling_special_list):
            if re.match(c, cmd) and h == type:
                return True
                
        return False
    
    # ----------------------------------------------------------------------- #
    def sendline(self, line): 
        """
        send line + EOL
        """

        # increase cmd counter
        self.counter_command += 1 
           
        # all output
        o = ''

        prompt_changed = self.is_command(cmd=line, type='$promptchange')
        is_enable = self.is_command(cmd=line, type='$enable')
        is_debug = self.is_command(cmd=line, type='$debug')
        is_nowait = self.is_command(cmd=line, type='$nowait')

        self.print_debug_message(\
            'L.sendline(): line=[%s], Prompt:%r, Enable:%r, Debug:%r' % \
            (line, prompt_changed, is_enable, is_debug), DEBUG_MSG_VERBOSE)

        if is_enable:
            self.stage = 'enable' 

        if is_debug: 
            o += self.set_debug_dest_to_me()

        self.child.send(line + self.EOL)

        if prompt_changed: 
            o += self.parse_prompt() 
            self.make_prompt_action_list()
            
        return o

    # ----------------------------------------------------------------------- #
    def sendline_expect(self, line):
        """
        sendline + expect
        """ 
        
        _line = line.strip()

        need_prettylog = self.is_command(cmd=_line, type='$prettylog')

        if need_prettylog:
            if self.log_format == 'Date_Time_Session_Command': 
                title = '%s, %s, %s' % (\
                    datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                    self.session, _line)
            
                ll = (TERM_WIDTH - 2 - len(title))//2
                rl = TERM_WIDTH - 2 - ll - len(title)

                open_line = '\n' + '%s %s %s' % ('-'*ll, title, '-'*rl) + '\n'
            else: 
                open_line = '\n' + '-'*TERM_WIDTH + '\n'
            
            close_line = '\n' + '~'*TERM_WIDTH + '\n'
       
            sys.stdout.write(open_line)

        o1 = self.sendline(line)

        # if it is reload command, short timeout + no prompt parse
        if self.is_command(cmd=line, type='$nowait'):
            r, o = self.expect(timeout=5, looking_for_prompt=False)
        else: 
            r, o = self.expect()

        if need_prettylog:
            sys.stdout.write(close_line)

        if re.search('nvalid input|yntax error', o):
            self.counter_invalid_command += 1

        return o
    
    # ----------------------------------------------------------------------- #
    def send(self, lines='', delimiter='\n', raw_mode=True):
        '''
        Major external method to send singl/multiple command(s) to session

        send --> sendline_expect
                 |--> sendline
                 |    |--> child.send()
                 |--> expect()
        '''
        output = ''

        for line in lines.split(delimiter): 
            # don't send empty|comment line if not raw_mode
            cmd = line.strip()
            if not raw_mode and (cmd == '' or cmd[0] == '#'):
                continue
    
            self.print_debug_message(
                msg='\n\nsending cmd[%s] to device...\n' % cmd,
                msg_level=DEBUG_MSG_VERBOSE)

            o = self.sendline_expect(cmd)
            output += o
        
        return output

    # ----------------------------------------------------------------------- #
    def close(self):
        self.child.close()

# --------------------------------------------------------------------------- #
class PYSConfigParser:
    """
    Local version of ConfigParser

    The official ConfigParser in python doesn't take colon(:) as part of value.
    But most login prompts like "longin:" or "username:", so have to make a 
    wheel myself.
    """
    def __init__(self):
        # by default is DefaultValues section
        self.dict = {}
        self.values  = {}

        self.dict['DefaultValues'] = {}
        self.values['DefaultValues'] = []

        self.sections = ['DefaultValues']

        self.delimiter = '='

    def read(self, filename='./pysession.conf'):
        with open(filename, 'r') as f:
            conf_lines = f.readlines()
        f.close
       
        section = 'DefaultValues'

        for line in conf_lines:
            line = line.strip()
            if len(line) == 0 or line[0] == '#':
                continue

            re_section = re.match('^\[(.*)\]$', line)
            if re_section:
                section = re_section.group(1)

                if section not in self.sections: 
                    self.sections.append(section) 
                    self.dict[section] = {}
                    self.values[section] = []

                continue

            re_key_value = re.match('(.*)%s(.*)' % self.delimiter, line)
            if re_key_value:
                k, v = map(str.strip, re_key_value.groups())
                self.dict[section][k] = v
                continue

            self.values[section].append(line)

            if section == 'Delimiter':
                self.delimiter = line

# --------------------------------------------------------------------------- #
class PYSLogger:
    """
    local logger module, with this we can output to 2 stdout and pysession
    log file
    """
    def __init__(self, log_file_name="pys_log_file"):
        self.terminal = sys.stdout
        self.log = open(log_file_name, 'w')

    def write(self, message):
        self.flush()
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

# --------------------------------------------------------------------------- #
class PYSLib:
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

    5) get_input(message=''):
       wrapper of raw_input(), return dict {input=$input}
    """ 
   
    # ----------------------------------------------------------------------- #
    def get_input(self, message):
        return {'input':raw_input(message)}

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
    def psleep(num_sec, reason='', pprint='True'):
        """
        pretty sleep
        """
    
        if num_sec < 0:
            return 0
   
        if pprint: 
            print PYSLib.pline2('sleeping %d seconds: %s' % (num_sec, reason))
        else:
            print '\n'

        for i in range(num_sec):
            if i % 10 == 0:
                print 'sec:%4d' % i,
            time.sleep(1)
            print '.',
            sys.stdout.flush()

            if i % 10 == 9:
                print '\n',
        
        if pprint: 
            print PYSLib.pline2('END of sleeping %d seconds' % num_sec)
    
    # ----------------------------------------------------------------------- #
    @staticmethod
    def pline1(line, char='-'): 
        """
        pline1 - pretty line 1
        ------------------------- LINE ------------------------ 
        """
        l = len(line) + 2
        ll= (78-l)/2 
        return '%s  %s  %s' % (char*ll, line, char*(78-l-ll))

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
        return '\n%s\n!%s%s%s!\n%s' % ('!'*80, ' '*ll, line, ' '*(78-l-ll), \
            '!'*80)

"""
Main part for pysession.py, used for quick run/test
"""

def usage():
    print '''
Usage: %s -C <cmdfile> -c <cmds> -s <session> -i <userid> [-p <password>] [-e <enable_password]

arguments:
    -c, --cmdlist          list of commands seperated by ; like "show ver; show int brief; show mac"
    -C, --cmdfile          command file containing list of commands send to router
    -s, --session          session of list of sessions separated by ; 
                           like -s "telnet 10.1.1.1" or -s "telnet 10.3.22.1 3055; ssh -l admin gw1.company.com"
    -u, --userid           user id
    -p, --password         login password of user id (you can leave it blank and provide it later in non-echo way)
    -e, --enable_password  enable password (you can leave it blank and provide it later in non-echo way)
    ''' % sys.argv[0]

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:C:s:u:p:e:", 
            ["cmdlist=", "cmdfile=", "session=", "userid=", "password=",\
             "enable_password=",])
    except getopt.GetoptError:
        print 'getopt error'
        usage()
        sys.exit(2)

    # initialize the variables
    cmds = ''
    session_list = []
    session, userid, password, enable_password, = '', '', '', ''
    cmd_delimiter = '\n'

    # parse the sys.argv
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-c', '--cmdlist'):
            cmds = arg
            cmd_delimiter = ';'
        elif opt in ('-C', '--cmdfile'):
            with open(arg, 'r') as f:
                cmds = f.read()
            f.close()
        elif opt in ('-s', '--session'):
            session_list = map(str.strip, arg.split(';'))
        elif opt in ('-u', '--userid'):
            userid = arg
        elif opt in ('-p', '--password'):
            password = arg
        elif opt in ('-e', '--enable_password'):
            enable_password = arg

    if cmds == '' or len(session_list) == 0:
        if cmds == '': 
            print 'error: no router commands given.....'
        
        if len(session_list) == 0:
            print 'error: no router sessions given.....'
        
        usage()
        sys.exit(2)

    print '\n' + PYSLib.pline1('List of Sessions')
    print '\n'.join(session_list)

    print '\n' + PYSLib.pline1('List of Commands')
    print cmds

    for session in session_list: 
        router = pysession(session=session, user=userid, password=password, 
            enable_password=enable_password)

        router.send(cmds, delimiter=cmd_delimiter)

        total_sec = int(time.time() - router.start_time) 
        elapse_time = '%d min %d sec' % (total_sec/60, total_sec%60) 
        sleep_time = '%d min %d sec' % (router.sleep_time/60, router.sleep_time%60) 
        file_size_in_KB = '%d KB' % int(os.stat(router.log_file_name).st_size/1000)

        print '\n' + PYSLib.pline2('SUMMARY - %s' % session)
        print '       script running time :', elapse_time
        print '             sleeping time :', sleep_time
        print '           number of lines :', router.counter_line
        print '        number of commands :', router.counter_command
        print 'number of invalid commands :', router.counter_invalid_command
        print '   size of log output file :', file_size_in_KB
    
