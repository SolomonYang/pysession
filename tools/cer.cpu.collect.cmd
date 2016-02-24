##############################################################################
# Special Commands for BrcdDataCollector.py
# 1) !DO LOOP <n>
# 2) !DO ENDLOOP 
# 3) !DO SLEEP <N> SECONDS 
# 4) !DO SET DEBUG DEST
##############################################################################

# Also  you can use “dm monitor” for  going from console to  the OS mode.
# Please collect the below data in the OS mode during when the LP task is busy 
# (when OSPF flap is seen).
# 1. show task lp (execute 4 times)
# 2. show cpu histogram hold-time above 100 (4 times)
rconsole
enable
dm monitor
!DO LOOP 4
    show task
    show cpu histogram hold above 100
    !DO SLEEP 10 SECONDS
!DO ENDLOOP

# 3.  Please collect below, cpu samples (for 5 minutes during when the issue 
#     seen), if the customer agrees as it would enable to know, which function 
#     LP task is executing, when it is 72% busy.
# set sample-rate 100  first execute this command to set the sample-rate
# set bm-format sym  Next, execute this command to show the output in human readable format
# show sample  This command starts actual collection of the data
set sample-rate 100 
set bm-format sym
!DO LOOP 10
    show sample
    !DO SLEEP 30 SECONDS
!DO ENDLOOP

# 4. Once, the step (3) is done, the following command should be executed to 
#    bring the device back to the default state.
set sample-rate 0

# exit from MP-OS>
exit
exit
