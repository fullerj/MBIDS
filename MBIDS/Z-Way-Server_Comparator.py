###############################################################################
# Z-Way-Server_Comparator.py
#
# Author: Jonathan Fuller
#
# Evaluates captured packets stored in Captured_Packets_Log 
#  with log captures on the Z-Wave gateway.
#  If the captured packets are not in the Z-Wave gateway log file, it is likely
#     that they were injected from a rogue device or SDR

import paramiko
import logging
from __builtin__ import True, False
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * #@UnusedWildImport
from scapy.modules.gnuradio import * #@UnusedWildImport
import sys

#****************************************************************************
class detect_RogueOne(Automaton):

#----------------------------------------------------------------------------    
    def parse_args(self, host, usrn, psswd, *args, **kargs):
        Automaton.parse_args(self, *args, **kargs)
        
        self.ssh = ''
        self.host = host
        self.usrn = usrn
        self.psswd = psswd
        self.qty_packets = 0
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------        
    @ATMT.state(initial=1)
    def BEGIN(self):
        print "[+] Detecting Rouge One \n"
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------    
    # Open SSH connection to Z-Wave gateway 
    @ATMT.condition(BEGIN)
    def OPEN_SSH(self):
        print "[+] Connecting to gateway..."
        sec_shell = paramiko.SSHClient()
        sec_shell.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sec_shell.connect(self.host, username=self.usrn, password=self.psswd)
        print "[+] SSH Opened: Connected to Z-Wave Gateway\n"   
        self.ssh  = sec_shell
        
        raise self.WAITING()
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------          
    # A sleep is needed so the Z-Wave gateway can store transmissions in the 
    # log file.  If it is scanned too early, the Comparator will considered 
    # evaluated packets as a known-good packet from an impersonating device.
    # A sleep time of >= 20 seconds is needed to ensure packets sent from the
    # gateway or received are logged in /var/log/z-way-server.log.
    # After sleep, begin scanning log file
    @ATMT.state()
    def WAITING(self):
        """Wait enough time for packets to enter log file on gateway """
        print "[+] WAITING... "
        
        # Sleep 20 seconds and print countdown to the screen
        seconds = 10
        for i in xrange(seconds,0,-1):
            time.sleep(1)
            sys.stdout.write(str(i) + " ")
            sys.stdout.flush()
            
        print '\n'   
        
        logFile = open("IDS_Log", "a") 
        logFile.write("\n")
        logFile.close()          
        raise self.LOG_SCANNING()
        pass
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
    @ATMT.state()
    def LOG_SCANNING(self):    
        
        self.qty_packets = self.qty_packets + 1
        
        gateway = self.ssh
        sftp_client = gateway.open_sftp()
        
        print "[+] Begin scanning..."
        
        queue = open('Captured_Packets_Log', 'r' )
        lines = queue.readlines()

        # If there are packet captures in the Captured_Packets_Log file, 
        #  begin comparison
        if lines:
            inject = lines[0].strip()
        
            
            date_time = inject[0:20]
            
            srcID = inject[22]
            dstID = inject[24]
            cmdCl = inject[29:31]
            
            payload = cmdCl + " " + prep_payload(inject[32:])
            
            queue = open('Captured_Packets_Log', 'w' )
            queue.write( ''.join( lines[1:] ) )
        
        
            before_time = sec_before(date_time)
             
            file = sftp_client.open('/var/log/z-way-server.log')
            
            valid = True      
            loopBack = False
        
            # Open z-way-server.log and scan each line for capture packet
            # If the source ID of the capture packet is 1, look for 
            #  the time stamp, "SENDING" tag, and the payload.
            try:
            
              for line in file:
                    
                    if srcID == '1':
                        if (((date_time or before_time) in line) 
                            and "SENDING"  in line and payload  in line):
                          
                            valid = True                      
                            break
                        
                        else:    
                            valid = False 
                            
                    elif srcID == dstID:
                        loopBack = True
                                          
            finally:
               file.close()
            
            # If the captured packet is not found in the log, it was injected 
            #  from a non-networked Z-Wave devices (rogue) or an SDR
            # Log the misuse in the IDS_Log file
            if valid == False:
                logFile = open("IDS_Log", "a") 
                logFile.write(date_time + 
                        "] Clean packet from impersonating device \n")
                logFile.close()  
                
            if loopBack == True:
                logFile = open("IDS_Log", "a") 
                logFile.write(date_time + 
               "] Source ID & Destination ID are the same. Injected Packet\n")
                logFile.close()  
            
            loopBack = False
            valid = True

        # If there are no packet captures in the Captured_Packets_Log file, 
        #  begin WAITING       
        else:
            queue.close()
            raise self.WAITING()
       
        
        # Evaluate 5 captured packets then resume sleeping.
        # This ensures that if packets are sent or received by the controller,
        #  they will surely be in the z-way-server.log file.
        if self.qty_packets <= 5:
            raise self.LOG_SCANNING()
        else:
            queue.close()
            self.qty_packets = 0
            raise self.WAITING()
#----------------------------------------------------------------------------            
#****************************************************************************           

#****************************************************************************     
# Add space in between bytes           
def prep_payload(payload):
    sep_payload = ''
    for i in range (0, len(payload)+1):
        if i % 2 == 0 and i != 0:
            sep_payload = sep_payload + payload[i-2:i] + " "
    return sep_payload       
#****************************************************************************

#****************************************************************************
# Decrement time by 1 second
def sec_before(time):

    start = time[:20]
    second = int(time[18:20])
    minute = int(time[15:17])

    second = second - 1    
    if second < 0:
        second = 60 + second
        minute = minute - 1

    if len(str(second)) == 1:
        second = "0" + str(second)
        
    if len(str(minute)) == 1:
        minute = "0" + str(minute)
                   
    before = start[:14] +  ":" + str(minute) + ":" + str(second)

    return before   
#****************************************************************************

#****************************************************************************
''' MAIN '''
if __name__ == "__main__":
    
    detect_RogueOne('10.1.0.66', 'pi', 'cedet2').run()
    
##############################################################################
  
