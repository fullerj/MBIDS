###############################################################################
# Enhanced_main.py - MBIDS_PLUS
#
# Author: Jonathan Fuller
#
# Similar to main.py
# The enhancement strategy logs packets classified as known-good packets and 
#  logs them separately in Captured_Packets_Log file for further evaluation.
#
#  The enhancement strategy is then performed on the packets logged in 
#   Captured_Packets_Log file.
#   Z-Way-Server_Comparator.py evaluates the missed packets.
#   If the known-good packet is from node ID 1, it must be from the controller.
#   The controller logs all of its transmissions in /var/log/z-way-server.log
#   Captured known-good packets from node ID 1 are compared to the log file.
#   If it is not in the log file, it was not sent by the controller but instead
#   injected from an impersonating device acting as node ID 1.  It is therefore
#   added to the IDS_Log file as an "Impersonating Device"
#   The additional checking is done in the Z-Way-Server_Comparator.py file.

import logging
from __builtin__ import True, False
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * #@UnusedWildImport
from scapy.layers.ZWave import * #@UnusedWildImport
from scapy.modules.gnuradio import * #@UnusedWildImport
from scapy.layers.ZWave import * #@UnusedWildImport
from scapy.layers.gnuradio import * #@UnusedWildImport
import urllib2
import json
import datetime
import Inspect_Payload
import Checksums

#****************************************************************************
class MBIDS_PLUS(Automaton):
    
#----------------------------------------------------------------------------     
    def parse_args(self, homeID, *args, **kargs):
        Automaton.parse_args(self, *args, **kargs)
        self.homeIdentification = homeID
        load_module('gnuradio')
        
        self.srcdID = ''
        self.dstID = ''
        self.cmdcl = ''
        self.length = 0
        self.pload = ''
        self.header = ''
        self.routed = ''
#---------------------------------------------------------------------------- 

#----------------------------------------------------------------------------         
    @ATMT.state(initial=1)
    def BEGIN(self):
        #load_module('gnuradio')
        #switch_radio_protocol("Zwave")
        #time.sleep(2)
        print "BEGIN"
        raise self.WAITING()
#---------------------------------------------------------------------------- 

#---------------------------------------------------------------------------- 
    @ATMT.state()
    def WAITING(self):
        """Wait for the turn on frame """
        print "WAITING\n"
        pass
#---------------------------------------------------------------------------- 

#---------------------------------------------------------------------------- 
    @ATMT.receive_condition(WAITING)
    def INTRUSION_DETECTION(self, packet_receive):
     
        time_now = set_time(str(datetime.datetime.now()))

        validSrc = validDst = validCC = validLen = False
        validPloadLen = loopBack = False
        validRouted = True
        
        
        if ZWaveReq in packet_receive:
            


            
            # If home ID is accurate, proceed
            if (hex(packet_receive[ZWaveReq].homeid).split('x')[1] == 
                self.homeIdentification and 
                Checksums.verify_checksum(packet_receive, ZWaveReq) == True):
               
           
                
                (self.srcID, self.dstID, self.length, self.cmdcl, self.header,
                    self.pload, self.routed) = parse_Packet(packet_receive, 1)
                    
                # length of the packet must be <= 64 bytes if singlecast 
                if self.length <= 64:

                    validLen = True
                
                # check for valid source id
                for row in devices_cmdclasses:
                    
                    if self.routed == 1:
                        validRouted = parse_Routed(self)
               
                        validLen = True 
                        validSrc = True 
                        validDst = True
                        validCC = True
                        validPloadLen = True
                        parse_Packet(packet_receive, 2)
                        
                    # if header is 1, packet is singlecast. If routed is 1
                    # evaluate frame as a routed packet instead
                    elif self.header == 1:
                        
                            if int(self.srcID) == int(row[0]):
                                validSrc = True
                            
                            # if destination id is valid, continue
                            if int(self.dstID) == int(row[0]):
                                validDst = True
                              
                                # if source id is valid, check for supported 
                                # command class
                                for cc in row[1:]:
                                       
                                    if self.cmdcl == '1':
                                        validCC = True
                                        break
                                    elif self.cmdcl == '0':
                                        validCC = True
                                        break
                                    elif self.cmdcl == cc:                                                
                                        validCC = True
                                        break
                            
                            # if the command class is valid, evaluate the 
                            # command and then remaining payload
                            if validCC == True:
                                    
                                validPloadLen = validatePayload(self)    
                            
                            # if the source ID and destination ID are equal, it
                            # is a loopback error and not possible under normal
                            # network operations.  Misuse case!
                            if self.srcID == self.dstID:
                                loopBack = True

                    elif self.header == 5:
                        if self.srcID == '1':
                            validSrc = True
                            
                        if self.length <= 22:
                            validLen = True
                            
                        if self.cmdcl == '20':
                            validCC = True
                            
                        if len(self.pload) <= 22:
                            validPloadLen = True
                        
                        validDst = True
                     
                    # This allows discovery of headers that are not supposed to
                    # be used per ITU-T G.9959 Recommendation.  
                    # e.g., RaZberry Pi uses Header 5 in some cases.  Header 5
                    # is reserved and should not be used.                   
                    else:
                        print "Header is ", self.header
                        validLen = True 
                        validSrc = True 
                        validDst = True
                        validCC = True
                        validPloadLen = True
 
 
            # MSDU length is incorrect.       
            if (validLen == False and 
                Checksums.verify_checksum(packet_receive, ZWaveReq) == True):

                logFile = open("IDS_Log", "a") 
                logFile.write("[" + time_now + "] " 
                              + "Packet is too long. Length = " 
                              + str(self.length)+"\n")             
                logFile.close()

            # Source ID is not recognized
            elif (validSrc == False and 
                  Checksums.verify_checksum(packet_receive, ZWaveReq) == True):

                logFile = open("IDS_Log", "a") 
                logFile.write("[" + time_now + "] " 
                              + "Source ID is invalid. Source ID = " 
                              + str(self.srcID)+"\n")
                logFile.close()                

            # Source ID is not recognized
            elif (validDst == False and 
                  Checksums.verify_checksum(packet_receive, ZWaveReq) == True):
  
                logFile = open("IDS_Log", "a") 
                logFile.write("[" + time_now + "] " 
                              + "Destination ID is invalid. Destination ID = " 
                              + str(self.dstID)+"\n")
                logFile.close()                
          
            # Source ID does exists.  Now, check if the correct 
            # command class is used.       
            elif (validCC == False and 
                  Checksums.verify_checksum(packet_receive, ZWaveReq) == True):
   
                logFile = open("IDS_Log", "a") 
                logFile.write("[" + time_now + "] " +
                            "Command Class is invalid. Command Class = " 
                            + str(self.cmdcl)+"\n")
                logFile.close()                         
              
            # Command class is supported but payload length is incorrect.       
            elif (validPloadLen == False and 
                  Checksums.verify_checksum(packet_receive, ZWaveReq) == True):

                logFile = open("IDS_Log", "a") 
                logFile.write("[" + time_now + "] " 
                              + "Payload length is invalid. Payload length = " 
                              + str(len(self.pload))+"\n")
                logFile.close()         
       

            # Invalid Routed Frame       
            elif (validRouted == False and 
                  Checksums.verify_checksum(packet_receive, ZWaveReq) == True):
                
                logFile = open("IDS_Log", "a") 
                logFile.write("[" + time_now + "] " 
                              + "Invalid Routed Frame" 
                              + str(len(self.pload))+"\n")
                logFile.close()         

            # if the packet checks out, verify checksum to ensure the packet 
            # is not malformed   
            else:
                if Checksums.verify_checksum(packet_receive, ZWaveReq) == True:
    
                    logFile = open("IDS_Log", "a") 
                    logFile.write(#"[" + time_now + "] " + "Good Packet: " +
                                  str(parse_Packet(packet_receive, 3)) 
                                  + "-> End Good packet\n")
                    logFile.close()  
                    
                    if self.srcID == '1' or loopBack == True:
                            capture_packet = ("[" + time_now + "] " 
                            + self.srcID + " " + self.dstID + " " 
                            + str(self.length) + " " + self.cmdcl 
                            + " " + self.pload)
                            logFile = open("Captured_Packets_Log", "a") 
                            logFile.write(capture_packet + "\n")
                            logFile.close()

#****************************************************************************

#****************************************************************************
def set_time(time):
    start = time[:19]
    second = int(time[17:19])
    minute = int(time[14:16])
 
    #print "second: ", second
    second = second - 22    # 22 seconds behind the raspberry pi
    if second < 0:
        second = 60 + second
        minute = minute - 1

    if len(str(second)) == 1:
        second = "0" + str(second)
        
    if len(str(minute)) == 1:
        minute = "0" + str(minute)
                        
    offset = start[:14] +  str(minute) + ":" + str(second)

    return offset
#****************************************************************************

#****************************************************************************
# Parse Z-Wave Packet
def parse_Packet(packet_receive, function):
    srcID = hex(packet_receive[ZWaveReq].src).split('x')[1]
    dstID = hex(packet_receive[ZWaveReq].dst).split('x')[1]
    length = int(hex(packet_receive[ZWaveReq].length).split('x')[1], 16)
    cmdcl = hex(packet_receive[ZWaveReq].cmd).split('x')[1]
    header = packet_receive[ZWaveReq].headertype
    routed = packet_receive[ZWaveReq].routed
    pload = ''
                
    if Raw in packet_receive:
        pload =  ''.join( [ "%02X" % ord( x ) 
            for x in packet_receive[Raw].load] )
    
    # return values
    if function == 1:
        return srcID, dstID, length, cmdcl, header, pload, routed
    
    # pritn values vertically
    elif function == 2:
        print "srcID: ", srcID
        print "destID ", dstID
        print "length: ", length
        print "CmdCl: ", cmdcl
        pload = ''
        if Raw in packet_receive:
            pload =  ''.join( [ "%02X" % ord( x ) 
                               for x in packet_receive[Raw].load] )
            print "payload: ", pload
            print "pload len ", len(pload)/2
        print "\n"
    
    # return values in a horizontal string   
    elif function == 3:
        return ("srcID: ", srcID, " destID ", dstID, " length: ", length, 
                                    " CmdCl: ", cmdcl, " payload: ", pload)
#****************************************************************************

#****************************************************************************
# Parse routed packet - based on ITU-T G.9959 Recommendation
#
# [00] [Hops|Hops to Do] [NodeIDs to hop through] [CmdCl | Cmd | Payload]
#****************************************************************************
def parse_Routed(self):
    
    validRouted = True
    
    hops = self.pload[0:1]
    hopsDone = self.pload[1:2]
    validNode = True

    # Check next bytes for ID on the network
    for i in range(0,len(hops)):
                    
        nID = self.pload[2:4]
        remainingLoad = self.pload[4:]
     
        for nodeID in devices_cmdclasses:
            
            # Check all nodes IDs in packet to make sure they exist on the 
            # network. If they do not, it is invalid. If only one is invalid,
            # break from the loop
            if int(nID) != int(nodeID[0]):  
                validNode = False
            else:
                validNode = True    
    

    if validNode == True:

        # Now that we have our final Node ID in the payload, check to see if 
        # the command class it is sent is supported by the receiving node
        for row in devices_cmdclasses:
            if int(self.dstID) == int(row[0]):
                
                for cc in row[1:]:                  
                    if remainingLoad[0:2] == cc:                                                
                        validRouted = evaluateRoutedPayload(self, 
                                        remainingLoad[0:2], remainingLoad[2:])
    
    # hopcount has to be less than or equal to specified hops
    if int(hopsDone) <= int(hops):    
        return validRouted

#****************************************************************************        
# Validate Payload
def validatePayload(self):
    # NoOperation
    if self.cmdcl == '0':
        validPloadLen = Inspect_Payload.NoOP(self.pload)                  
                               
    elif self.cmdcl == '1':
        validPloadLen = Inspect_Payload.CallNIF(self.pload, self.srcID, 
                                                                nodeInfoFrames)
    
    # Basic
    elif self.cmdcl == '20':
        validPloadLen = Inspect_Payload.Basic(self.pload)
                                        
    # SwitchBinary        
    elif self.cmdcl == '25':
        validPloadLen = Inspect_Payload.BinarySwitch(self.pload)


    # SceneActuatorConf
    elif self.cmdcl == '2c':
        validPloadLen = Inspect_Payload.ScenceActuatorConf(self.pload)         
                                
    # CRC16Encap       
    elif self.cmdcl == '56':
        validPloadLen = Inspect_Payload.Crc16Encap(self.pload)                                
                                    
    # Configuration
    elif self.cmdcl == '70':
        validPloadLen = Inspect_Payload.Configuration(self.pload)
  
    # Protection   
    elif self.cmdcl == '75':
        validPloadLen = Inspect_Payload.Protection(self.pload)   
        
    # Association        
    elif self.cmdcl == '85':
        validPloadLen = Inspect_Payload.Association(self.pload)
                                    
    # Version
    elif self.cmdcl == '86':
        validPloadLen = Inspect_Payload.Version(self.pload, self.srcID, 
                                    self.dstID, ZWVersion, devices_cmdclasses)
                                                                                                                  
    # Security
    elif self.cmdcl == '98':
        validPloadLen = Inspect_Payload.Security(self.pload)                     
           
    return validPloadLen
#****************************************************************************

#****************************************************************************        
# Validate Payload
def evaluateRoutedPayload(self, cmdcl, pload):
    # NoOperation
    if cmdcl == '0':
        validPloadLen = Inspect_Payload.NoOP(pload)                  
                               
    elif cmdcl == '1':
        validPloadLen = Inspect_Payload.CallNIF(pload, self.srcID, 
                                                                nodeInfoFrames)
    
    # Basic
    elif cmdcl == '20':
        validPloadLen = Inspect_Payload.Basic(pload)
                                        
    # SwitchBinary        
    elif cmdcl == '25':
        validPloadLen = Inspect_Payload.BinarySwitch(pload)


    # SceneActuatorConf
    elif cmdcl == '2c':
        validPloadLen = Inspect_Payload.ScenceActuatorConf(pload)         
                                
    # CRC16Encap       
    elif cmdcl == '56':
        validPloadLen = Inspect_Payload.Crc16Encap(pload)                                
                                    
    # Configuration
    elif cmdcl == '70':
        validPloadLen = Inspect_Payload.Configuration(pload)
  
    # Protection   
    elif cmdcl == '75':
        validPloadLen = Inspect_Payload.Protection(pload)   
        
    # Association        
    elif cmdcl == '85':
        validPloadLen = Inspect_Payload.Association(pload)
                                    
    # Version
    elif cmdcl == '86':
        validPloadLen = Inspect_Payload.Version(pload, self.srcID, 
                                    self.dstID, ZWVersion, devices_cmdclasses)
                                                                                                                  
    # Security
    elif cmdcl == '98':
        validPloadLen = Inspect_Payload.Security(pload)                     
           
    return validPloadLen
#****************************************************************************

#****************************************************************************
''' RaZberry Cooperation IDS '''
# base url for Z-Way server
IP = "10.1.0.66"
zwayBase = "http://"+IP+":8083"

# device list, empty upon initialization
device_list = dict()

# matrix to store node IDs and command classes associated with the node
devices_cmdclasses = []  

nodeInfoFrames = []

ZWVersion = ''

# //----------------- GET ALL Z-WAVE DEVICES ------------------------//
def getZWayDevices():

    # url request to initiate json response and gather devices
    req = urllib2.Request(zwayBase + '/ZWaveAPI/Data/0')
    req.get_method = lambda: 'GET'

    # try/except to call the url
    # get the result, else print the error
    result = None
    try:
        result = urllib2.urlopen(req)
    except urllib2.URLError, e:
        print e.reason 
     
    #device_list = dict() 
    #global device_list
    # ensure result is received, decode the  result and convert
    # into a device list
    if(result != None):
        result_to_string = result.read().decode('utf8')

        if(result_to_string != ''):
            device_list = json.loads(result_to_string)
    
    for controller in device_list['controller']:
        for homeId in device_list['controller'][controller]['homeId']:
            if homeId == 'value':
                #signed to unsigned, unsigned to hex, hex to string
                homeIdentification = hex(device_list['controller']
                                         [controller]['homeId'][homeId] & 
                                         0xffffffff).split('x')[1]
                

    for node in device_list['devices']:
        row = []
        row.append(str(node))
        for instance in device_list['devices'][node]['instances']:
            for cmdCl in (device_list['devices'][node]['instances']
                                                [instance]['commandClasses']):
                for command in (device_list['devices'][node]['instances']
                                        [instance]['commandClasses'][cmdCl]):
                    if command == 'name':#  and node != str(1):
                        command = (device_list['devices'][node]['instances']
                                   [instance]['commandClasses'][cmdCl]['name'])
                        row.append(hex(int(cmdCl)).split('x')[1])
        devices_cmdclasses.append(row)
    
    for controller in device_list['controller']:
        for zversion in device_list['controller'][controller]['ZWVersion']:
            if zversion == 'value':
                #signed to unsigned, unsigned to hex, hex to string
                    global ZWVersion
                    ZWVersion = (device_list['controller'][controller]
                                                    ['ZWVersion'][zversion])
    
    
    for node in device_list['devices']:
        row = []
        row.append(str(node))
        for data in device_list['devices'][node]['data']:
            if data == 'nodeInfoFrame':
                for num in device_list['devices'][node]['data'][data]['value']:
                    row.append(hex(num).split('x')[1])
        nodeInfoFrames.append(row)

    print "NIF"  
    for row in nodeInfoFrames:#devices_cmdclasses:
        print row  
    print '\n'
    print "CMDCL"
    for row in devices_cmdclasses:
        print row  
    print '\n'
    #print homeIdentification
    
    return homeIdentification   
#****************************************************************************

#****************************************************************************
if __name__ == "__main__":
    
    homeIdentification = getZWayDevices()
    load_module('gnuradio')
    MBIDS_PLUS(homeIdentification).run()
    
##############################################################################    
