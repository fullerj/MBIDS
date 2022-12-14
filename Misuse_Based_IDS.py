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

preceived = 0   
class anomaly_Detection(Automaton):
    def parse_args(self, homeID, *args, **kargs):
        Automaton.parse_args(self, *args, **kargs)
        self.homeIdentification = homeID
        
    @ATMT.state(initial=1)
    def BEGIN(self):
        load_module('gnuradio')
        #switch_radio_protocol("Zwave")
        print "BEGIN"
        self.last_pkt = None
        raise self.WAITING()

    @ATMT.state()
    def WAITING(self):
        """Wait for the turn on frame """
        print "WAITING\n"
        pass

    @ATMT.receive_condition(WAITING)

    def intrusion_detection(self, packet_receive):
        
        validSrc = False
        validDst = False
        validCC = False
        validLen = False
        validPloadLen = False
        global preceived
        if ZWaveReq in packet_receive:
            preceived = preceived+1
            print preceived
            
            # If home ID is accurate, proceed
            if (hex(packet_receive[ZWaveReq].homeid).split('x')[1] == 
                self.homeIdentification):
               
                srcID = hex(packet_receive[ZWaveReq].src).split('x')[1]
                dstID = hex(packet_receive[ZWaveReq].dst).split('x')[1]
                length = int(hex(packet_receive[ZWaveReq].length).split('x')[1]
                             , 16)
                cmdcl = hex(packet_receive[ZWaveReq].cmd).split('x')[1]
                header = packet_receive[ZWaveReq].headertype
                pload = ''
                
                if Raw in packet_receive:
                    pload =  ''.join( [ "%02X" % ord( x ) 
                                       for x in packet_receive[Raw].load] )
                    
                    
                validSrc = False
                validDst = False
                validCC = False
                validLen = False
                validPloadLen = False  
                length = 0 
                
                # check for valid source id
                for row in devices_cmdclasses:
                    
                    # length of the packet must be <= 64 bytes if singlecast 
                    if header == 1:
                        if length <= 64:
                            validLen = True
                        
                            if srcID == row[0]:
                                validSrc = True

                                
                            # if destination id is valid, continue
                            if dstID == row[0]:
                                validDst = True
                               
                    
                                # if source id is valid, check for supported 
                                # command class
                                for cc in row[1:]:
                                    if cmdcl == '1':
                                        validCC = True
                                        break
                                    elif cmdcl == '0':
                                        validCC = True
                                        break
                                    elif cmdcl == cc:                                                
                                        validCC = True
                                        break
                                    
                            
                            if validCC == True:
                                
                                # NoOperation
                                if cmdcl == '0':
                                    validPloadLen = noOP(pload)                  
                                
                                elif cmdcl == '1':
                                    validPloadLen = callNIF(pload, srcID)
                                # Basic
                                elif cmdcl == '20':
                                    validPloadLen = basic(pload)
                                        
                                # SwitchBinary        
                                elif cmdcl == '25':
                                    validPloadLen = binarySwitch(pload)
                                
                                # CRC16Encap       
                                elif cmdcl == '56':
                                    validPloadLen = crc16Encap(pload)
                                    
                                                                
                                # ZWavePlusInfo                                                                                                                                                                 
                                elif cmdcl == '5e':
                                    validPloadLen = zwaveplusinfo(pload)
                                    
                                # Configuration
                                elif cmdcl == '70':
                                    validPloadLen = configuration(pload)
 
                                # Association        
                                elif cmdcl == '85':
                                    validPloadLen = association(pload)
                                    
                                # Version
                                elif cmdcl == '86':
                                    validPloadLen = version(pload, dstID)
                                                                                                                  
                                # Security
                                elif cmdcl == '98':
                                    validPloadLen = security(pload)
                         

                                else:
                                    validPloadLen = True
                                    validCC = False                  

                                
                    elif header == 5:
                        if srcID == '1':
                            validSrc = True
                            
                        if length <= 22:
                            validLen = True
                            
                        if cmdcl == '20':
                            validCC = True
                            
                        if len(pload) <= 22:
                            validPloadLen = True
                        
                        validDst = True
                                        
                    else:
                        print "Header is ", header
                        validLen = True 
                        validSrc = True 
                        validDst = True
                        validCC = True
                        validPloadLen = True
 
 
            # MSDU length is incorrect.       
            if validLen == False and verify_checksum(packet_receive) == True:
                print "\n*****************total length"
                dissect_packet(packet_receive)
                logFile = open("IDS_Log", "a") 
                logFile.write("Packet is too long. Length = " 
                              + str(length)+"\n")
                logFile.close()

            # Source ID is not recognized
            elif validSrc == False and verify_checksum(packet_receive) == True:
                print "\n*****************source"
                dissect_packet(packet_receive)
                logFile = open("IDS_Log", "a") 
                logFile.write("Source ID is invalid. Source ID = " 
                              + str(srcID)+"\n")
                logFile.close()                

            # Source ID is not recognized
            elif validDst == False and verify_checksum(packet_receive) == True:
                print '\n*****************destination'
                dissect_packet(packet_receive)
                logFile = open("IDS_Log", "a") 
                logFile.write("Destination ID is invalid. Destination ID = " 
                              + str(dstID)+"\n")
                logFile.close()                
          
            # Source ID does exists.  Now, check if the correct 
            # command class is used.       
            elif validCC == False and verify_checksum(packet_receive) == True:
                print '\n*****************command class'
                dissect_packet(packet_receive)        
                logFile = open("IDS_Log", "a") 
                logFile.write("Command Class is invalid. Command Class = " 
                              + str(cmdcl)+"\n")
                logFile.close()                         
              
            # Command class is supported but payload length is incorrect.       
            elif (validPloadLen == False and verify_checksum(packet_receive) 
                  == True):
                print '\n*****************msdu length'
                dissect_packet(packet_receive)
                logFile = open("IDS_Log", "a") 
                logFile.write("Payload length is invalid. Payload length = " 
                              + str(len(pload))+"\n")
                logFile.close()                 
 
            # if the packet checks out, verify checksum to ensure the packet 
            # is not malformed   
            else:
                if verify_checksum(packet_receive) == False:
                    logFile = open("IDS_Log", "a") 
                    logFile.write("Malformed packet received.\n")
                    logFile.close()  

        
  
        #else:
            #print 'beaming info is 0 page 52 and 53 page 118 and 119'

    @ATMT.action(intrusion_detection)
    def alarm_off(self):
        time.sleep(0.25)
        print "SWITCH ALARM OFF "
        pkt = self.last_pkt[ZWaveReq].copy()
        pkt[Raw].load = "\x00"
        pkt.seqn += 1
        pkt.crc = None
        for _ in range(0,4):
            self.send(pkt)
        print "WAITING\n"

##############################################################################
''' PACKET DISSECT '''       
def dissect_packet(packet_receive):
    srcID = hex(packet_receive[ZWaveReq].src).split('x')[1]
    dstID = hex(packet_receive[ZWaveReq].dst).split('x')[1]
    length = int(hex(packet_receive[ZWaveReq].length).split('x')[1], 16)
    cmdcl = hex(packet_receive[ZWaveReq].cmd).split('x')[1]
    #header = packet_receive[ZWaveReq].headertype
    
    print "srcID: ", srcID
    print "destID ", dstID
    print "length: ", length
    print "CmdCl: ", cmdcl
    pload = ''
    if Raw in packet_receive:
        pload =  ''.join( [ "%02X" % ord( x ) 
                           for x in packet_receive[Raw].load] )
        print "payload: ", pload
        print "pload len ", len(pload)
    print "\n"


##############################################################################
''' COMMAND CLASSES '''
# Command Class 0x0
def noOP(pload):
    validPloadLen = False
    
    if pload[0:2] == '10' or pload[0:2] == '11':
        validPloadLen = True
  
    return validPloadLen
    
# Command Class 0x1
def callNIF(pload, srcID):   
    validPloadLen = False

    # Calling for NIF (GET)
    if srcID == '1':
        if pload[0:2] == '02':
            if pload[2:4] == '':
                validPloadLen = True

    # When a device responds to a NIF, the payload after index 12 contains all 
    # NIFS as specified by the RaZberry in /ZWaveAPI/Data/0
    else:
        if pload[12:] != '':
            for row in nodeInfoFrames:
                if srcID == row[0]:
                    NIFs = pload [12:]
                    for nif in range(0,len(NIFs)/2):
                        first = NIFs[0:2]
                        NIFs = NIFs[2:]
                        for nif in row[1:]:
                            if first.lower() == nif:
                                validPloadLen = True
                                break
                            else:
                                validPloadLen = False
    return validPloadLen


# Command Class 0x20
def basic(pload):
    validPloadLen = False
    # Ensure Set, Get or Report
    if pload[0:2] == '01' or pload[0:2] =='03':
        # If Set or Report, only 00 or FF
        if pload[2:4] == '00' or pload[2:4] == 'FF':
            # nothing should follow
            if pload[4:6] == '':
                validPloadLen = True  
    # Ensure Get
    elif pload[0:2] == '02':
        # Nothing should follow a Get command
        if pload[4:6] == '':
            validPloadLen = True 

    return validPloadLen

# Command Class 0x25
def binarySwitch(pload):
    validPloadLen = False
    # Ensure Set, Get or Report
    if pload[0:2] == '01' or pload[0:2] =='03':
        # If Set or Report, only 00 or FF
        if pload[2:4] == '00' or pload[2:4] == 'FF':
            # nothing should follow
            if pload[4:6] == '':
                validPloadLen = True  
    # Ensure Get
    elif pload[0:2] == '02':
        # Nothing should follow a Get command
        if pload[4:6] == '':
            validPloadLen = True 

    return validPloadLen

#command class 56
def crc16Encap(pload):   
    validPloadLen = False  
    # Encap
    if pload[0:2] == '01':
        # Validate crc-16 of encap packet  ex: checksum(56012503FF) == 7958 ??
        p = '56'+pload[0:-4]
        
        # if the encapsulated CC is 70...Check the payload
        if pload[2:4] == '70':
            # from 4 to -4 because its checks after CC 70 and before crc_ccitt
            encapCC = configuration(pload[4:-4])
            
            if encapCC == True:
                if crc_ccitt(p) == pload[-4:]:  
                    validPloadLen = True
                    
        elif crc_ccitt(p) == pload[-4:]:  
            validPloadLen = True 
            
    return validPloadLen

# command class 86
def version(pload, dstID):  
    validPloadLen = False     
    # Get
    if pload[0:2] == '11': 
        if pload[2:4] == '':
            validPloadLen = True

    # Report
    elif pload[0:2] ==  '12':
        # Z-Wave Library Type 
        # (wiki.micasaverde.com/index.php/ZWave_Command_Classes)
        # Controller_Static, Controller, Slave_Enhanced, Slave, Installer, 
        # Slave_Routing, Controller_Bridge, Dut
        if (pload[2:4]== '01' or pload[2:4]== '02' or pload[2:4]== '03' or 
            pload[2:4]== '04' or pload[2:4]== '05' or pload[2:4]== '06' or 
            pload[2:4]== '07' or pload[2:4]== '08'):

            # Z-wave Protocol version - zwayBase/ZWaveAPI/Data/0
            if pload [4:6] == ZWVersion:

                # Z-Wave protocol subversion 
                # (wiki.micasaverde.com/index.php/ZWave_Protocol_Version)
                if (pload[6:8] == '06' or pload[6:8] == '07' or 
                    pload[6:8] == '09' or pload[6:8] == '16' or 
                    pload[6:8] == '17' or pload[6:8] == '21' or 
                    pload[6:8] == '22' or pload[6:8] == '23' or 
                    pload[6:8] == '24' or pload[6:8] == '25' or 
                    pload[6:8] == '27' or pload[6:8] == '28' or 
                    pload[6:8] == '30' or pload[6:8] == '31' or 
                    pload[6:8] == '32' or pload[6:8] == '36' or 
                    pload[6:8] == '37' or pload[6:8] == '39' or 
                    pload[6:8] == '40' or pload[6:8] == '44' or 
                    pload[6:8] == '48' or pload[6:8] == '51' or 
                    pload[6:8] == '53' or pload[6:8] == '59' or 
                    pload[6:8] == '67' or pload[6:8] == '68' or 
                    pload[6:8] == '74' or pload[6:8] == '78' or 
                    pload[6:8] == '81' or pload[6:8] == '91' or 
                    pload[6:8] == '97' or pload[6:8] == '99'):

                    # Z-Wave protocol Application Version and Application 
                    # Subversion is specific to the device and not defined 
                    # by Z-Wave make sure they exist but cant be sure 
                    # what they are
                    if pload[8:12] != '':

                        # nothing else should follow
                        if pload[12:14] == '':

                            validPloadLen = True 
    
    #CommandClassGet 
    # if cmd is 13, it asks for CC version.  Check to make sure 
    # CC it is asking for exists        
    elif pload[0:2] ==  '13':
        for row in devices_cmdclasses:
            if dstID == row[0]:
                for cc in row[1:]:
                    if pload[2:4] == cc:
                        if pload[4:6] == '':
                            validPloadLen = True
    
    # CommandClassReport
    # device responds with 14                        
    elif pload[0:2] == '14':
        for row in devices_cmdclasses:
            if dstID == row[0]:
                for cc in row[1:]:
                    if pload[2:4] == cc:

                        if pload[4:6] == '01' or pload[4:6] == '02':

                            if pload[6:8] == '':
                                validPloadLen = True
    return validPloadLen


# Command Class 70
def configuration(pload):
    validPloadLen = False
    
    # Set or Report
    if pload[0:2] ==  '04' or pload[0:2] ==  '06':
        if len(pload) <= 8:
            validPloadLen = True
    # Get
    if pload[0:2] ==  '05':
        # There will be a value after 05 between 0 and 255 (00 and FF)
        if pload[2:4] != '':
            validPloadLen = True
    
    
    return validPloadLen

# Command Class 98
eighty = []
eightyone = []

def security(pload):
    validPloadLen = False
    
    global eighty
    global eightyone
    
    
    #  Supported Get, SupportedReport, SchemeGet, SchemeReport, 
    # NetworkKeySet, NetworkKeyVerify, SchemeInherit,  
    #  MessageEncapNonceGet
    if (pload[0:2] == '02' or pload[0:2] ==  '03' or pload[0:2] ==  '04' or 
       pload[0:2] ==  '05' or pload[0:2] ==  '06' or pload[0:2] ==  '07' or 
       pload[0:2] ==  '08' or pload[0:2] ==  'c1'):
        if len(pload) <= 2:
            validPloadLen = True
    
    # NonceGet
    elif pload[0:2] ==  '40':
        if pload[2:4] == '':
            validPloadLen = True
    
    # NonceReport - Messages are in pairs or greater.  If a previous 
    # nonce report does not exists, the message is probably a one time inject 
    # and therefore an error
    elif pload[0:2] ==  '80':
          
        if len(eighty) >= 20:
            eighty = []
        
        eighty.append(pload[2:])
        if len(eighty) > 0:
            for nonce_report in eighty:
                if nonce_report == pload[2:]:
                    validPloadLen = True
        
    
    # MessageEncap - Messages are in pairs or greater.  If a previous 
    # messsage encap does not exists, the message is probably a one time 
    # inject and therefore an error
    elif pload[0:2] ==  '81':
        
        if len(eightyone) >= 10:
            eightyone = []

        eightyone.append(pload[2:])
        if len(eightyone) > 0:
            for nonce_report in eightyone:
                if nonce_report == pload[2:]:
                    validPloadLen = True
        
    return validPloadLen                                                                                                               

# Command class 5e
def zwaveplusinfo(pload):
    validPloadLen = False
    
    # Get
    if pload[0:2] == '01':
        if pload[2:4] == '':
            validPloadLen = True
    # Report
    elif pload[0:2] == '02':
        # 2 - version, 4 - role, 6 - nodetype, 8.10 - installerIcon, 
        # 12.14 - devicetype
        if len(pload[2:]) <= 14:
            validPloadLen = True
        
    return validPloadLen 

# Command Class 85
def association(pload):
    validPloadLen = False
    
    # Ensure Set, Report
    if pload[0:2] == '01' or pload[0:2] ==  '03':
        if len(pload) <= 10:
            validPloadLen = True
    # Get
    elif pload[0:2] ==  '02':
        if pload[2:4] != '':
            if pload[4:] == '':
                validPloadLen = True
    
    # Remove
    elif pload[0:2] ==  '04':
        if len(pload[2:]) <= 4:
            validPloadLen = True 
    # GroupingsSet
    elif pload[0:2] ==  '05':
        if pload[2:4] == '':
            validPloadLen = True
    
    # GroupingsReport
    elif pload[0:2] ==  '06':
        validPloadLen = True
                   
    return validPloadLen


                                    
                                                                                                                                        
# Command Class 32
def meter(pload):   
    validPloadLen = False   
    # Get, Report, SupportedGet, SupportedReport, Reset
    if (pload[0:2] == '01' or pload[0:2] ==  '02' or pload[0:2] ==  '04' 
        or pload[0:2] ==  '05'):
            if len(pload) <= 1: 
                validPloadLen = True 
    return validPloadLen
        
# Command Class 26
def switchMultilevel(pload):
    validPloadLen = False
    # Set, Get, Report, StartLevelChange, StopLevelChange, 
    # SupportedGet, SupportedReport
    if (pload[0:2] == '01' or pload[0:2] ==  '02' or pload[0:2] ==  '03' or 
        pload[0:2] ==  '04' or pload[0:2] ==  '05' or pload[0:2] ==  '06' or 
        pload[0:2] ==  '07'):
        if len(pload) <= 4:
            validPloadLen = True 
    return validPloadLen
        
# Command Class 27
def switchAll(pload):
    validPloadLen = False
    # Set, Get, Report, On, Off
    if (pload[0:2] == '01' or pload[0:2] ==  '02' or pload[0:2] ==  '03' or
        pload[0:2] ==  '04' or pload[0:2] ==  '05'):
        if len(pload) <= 4:
            validPloadLen = True 
    return validPloadLen
        
# Command Class 2b
def sceneActivation(pload):
    validPloadLen = False
    # Set
    if pload[0:2] == '01':
        if len(pload) <= 4:
            validPloadLen = True     
    return validPloadLen

# Command Calss 31
def sensorMultilevel(pload):
    validPloadLen = False
    # SupportedGet, SupportedReport, Get, Report
    if (pload[0:2] == '01' or pload[0:2] ==  '02' or pload[0:2] ==  '04' 
        or pload[0:2] ==  '05'):
        if len(pload) <= 14:
            validPloadLen = True                         
    return validPloadLen       

# Command Class 72
def manufacturerSpecific(pload):
    validPloadLen = False
    # Ensure Set, Get, or Report
    if pload[0:2] ==  '04' or pload[0:2] ==  '05':                                    
        if len(pload) <= 14:
            validPloadLen = True 
    return validPloadLen

##############################################################################        
''' 8-bit Checksum '''
def verify_checksum(packet):
    p = bytearray(str(packet))
    p = p[8:-1]
    
    calc_crc = hex(reduce(lambda x, y: x ^ y, p, 0xFF))
    crc_byte = packet[ZWaveReq].get_field('crc').i2repr(packet, packet.crc)

    if (calc_crc == crc_byte): 
        return True
    else: 
        return False


''' 16-bit Checksum '''
POLYNOMIAL = 0x1021
PRESET = 0x1D0F

def _initial(c):
    crc = 0
    c = c << 8
    for _ in range(8):
        if (crc ^ c) & 0x8000:
            crc = (crc << 1) ^ POLYNOMIAL
        else:
            crc = crc << 1
        c = c << 1
    return crc

_tab = [ _initial(i) for i in range(256) ]

def _update_crc(crc, c):
    cc = 0xff & c

    tmp = (crc >> 8) ^ cc
    crc = (crc << 8) ^ _tab[tmp & 0xff]
    crc = crc & 0xffff

    return crc

def crc_ccitt(pload):
    crc = PRESET
    
    for _ in range(0, len(pload)/2):
        first = pload[0:2]
        pload = pload[2:]
        first = int(first,16)
    
        crc = _update_crc(crc,first)
    
    # return 4 character value.  If 1ca return 01ca  
    crc = ''.join( [ "%04X" % crc]) 
    return crc

##############################################################################
''' RaZberry Cooperation IDS '''
# base url for Z-Way server
zwayBase = "http://10.1.0.66:8083"

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
            for cmdCl in device_list['devices'][node]['instances'][instance]['commandClasses']:
                for command in device_list['devices'][node]['instances'][instance]['commandClasses'][cmdCl]:
                    if command == 'name':#  and node != str(1):
                        command = device_list['devices'][node]['instances'][instance]['commandClasses'][cmdCl]['name']
                        row.append(hex(int(cmdCl)).split('x')[1])
        devices_cmdclasses.append(row)
    
    for controller in device_list['controller']:
        for zversion in device_list['controller'][controller]['ZWVersion']:
            if zversion == 'value':
                #signed to unsigned, unsigned to hex, hex to string
                    global ZWVersion
                    ZWVersion = device_list['controller'][controller]['ZWVersion'][zversion]
    
    
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

##############################################################################
''' MAIN '''
if __name__ == "__main__":
    
    homeIdentification = getZWayDevices()
    load_module('gnuradio')
    anomaly_Detection(homeIdentification).run()