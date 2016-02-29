# pysession
pysession is a Python module for establishing sessions to network devices via ssh, telnet or console, signing in with provided login credentials, detecting device prompt, sending command and retrieving output. 

pysession is based on pexpect, so in other words, it is an extension of pexpect. Then what's the value of pysession? The purpose is to provide a simplified interface to access and controle network devices by hidding the lower-level interaction, like
* Loogin device (user id, password and enable password)
* Automatic device prompt detection during login process or after special commands like (config term, rconsole...)
* Page break (either entering page-break-free mode, or feeding space if seeing page-break)
