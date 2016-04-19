# pysession
pysession is a Python module for establishing sessions to network devices via ssh, telnet or console, signing in with provided login credentials, detecting device prompt, sending command and retrieving output. 

pysession is based on pexpect, so in other words, it is an extension of pexpect. Then what's the value of pysession? The purpose is to provide a simplified interface to access and controle network devices by hidding the lower-level interaction, like
* Login device (detecting prompts for user id, password and enable password, and handling accordingly)
* Automatic device prompt detection during login process or after special commands like (config term, rconsole...)
* Page break (either entering page-break-free mode, or feeding space if seeing page-break)
* Self-defined prompts and handling. (please see the below section for details

So as a user, you don't need to waste your efforts/time on the low-level interaction, instead you should focus on what commands to send and what output returns. 

## How to use
You can use pysessin either as a standalone tool or a python library for your own python program. 

* standalone tool, actually i use this way to test the library after making any changes
** ./pysession.py -s 'telnet 1.1.1.1 2001; telnet 1.1.1.1; ssh admin@1.1.1.2' -c 'show ver; show run; show ip route' -p pswd -e enablepswd
** Then this python script will login the sessions of -s paramenter and run the commands specified in -c argument. 

* python library
import pysession

rtr = pysession(session='telnet 10.1.1.1')
output = rtr.send('''
show ver
show run
show ip route
''')

## Self-defined prompts and handling
If your devices have unique/special/weird prompts, you don't need to modify the script to handle them, instead just change the "pysession.conf" file. 

Example #1, the device login prompt to ask for username is not "login:" or "username:", instead it is "Tell me who are you?". 

You can edit pysession.conf file to add one line unde [Prompt.Stage.Login]
Tell me who are you? = $user

Example #2, the terminal server asks if you want to clear the existing session
!!! tty is being used !!!
1 - Initiate a regular session
2 - Quit
Enter your option :

You just need to add one line like under [Prompt.Stage.Login]
1 - Initiate a regular session.*Enter your option : = 1$   
!! the ending $ means only sending "1" without return. 

