###############################################################################
# Inspect_Payload.py
#
# Author: Jonathan Fuller
#
# Contains payload inspectors for each command class
# This file acts as a whitelist for injected packets
#
# Only command classes number 1-11 are tested

import Checksums

#****************************************************************************
# 1
# NO OPERATION
# Command Class 0x0
def NoOP(pload):
    validPloadLen = False
    
    if pload[0:2] == '10' or pload[0:2] == '11':
        validPloadLen = True
        
    # no data = ping request from the controller
    elif pload[0:2] == '':
        validPloadLen = True

    else:
        validPloadLen = False
  
    return validPloadLen
#****************************************************************************

#***************************************************************************
# 2  
# NODE INFORMATION FRAME
# Command Class 0x1
def CallNIF(pload, srcID, nodeInfoFrames):   
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
                if int(srcID) == int(row[0]):
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
        else:
            validPloadLen = False

    return validPloadLen
#****************************************************************************

#****************************************************************************
# 3
# BASIC
# Command Class 0x20
def Basic(pload):
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
       
        if pload[2:4] == '':
            validPloadLen = True 
    
    else:
        validPloadLen = False

    return validPloadLen
#****************************************************************************

#****************************************************************************
# 4
# BINARY SWITCH
# Command Class 0x25
def BinarySwitch(pload):
  
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
          
    
    else:
        validPloadLen = False

    return validPloadLen
#****************************************************************************

#****************************************************************************
# 5
# SCENE ACTUATOR CONFIGURATION
# Command Class 2c
def ScenceActuatorConf(pload):
    validPloadLen = False
    
    # Set
    if pload[0:2] == '01':
        # duration must be <=127
        if int(pload[4:6], 16) <= 127:
            if pload[6:8] == '00' or pload[6:8] == '80':
                if len(pload)/2 <= 4:
                    validPloadLen = True  
    # Get   
    elif pload[0:2] == '02':
        if len(pload)/2 <= 1:
            validPloadLen = True  
    # Report
    elif pload[0:2] == '03':
        if len(pload)/2 <= 3:
            validPloadLen = True                          
    else:
        validPloadLen = False

    
    return validPloadLen
#****************************************************************************

#****************************************************************************
# 6
# CRC 16-BIT ENCAPSULATION
#command class 56
def Crc16Encap(pload):   
    validPloadLen = False  
    # Encap
    if pload[0:2] == '01':
        # Validate crc-16 of encap packet  ex: checksum(56012503FF) == 7958 ??
        p = '56'+pload[0:-4]
        
        # if the encapsulated CC is 70...Check the payload
        if pload[2:4] == '70':
            # from 4 to -4 because its checks after CC 70 and before crc_ccitt
            encapCC = Configuration(pload[4:-4])
            
            if encapCC == True:
                if Checksums.crc_ccitt(p) == pload[-4:]:  
                    validPloadLen = True
                    
        elif Checksums.crc_ccitt(p) == pload[-4:]:  
            validPloadLen = True 

    else:
        validPloadLen = False
            
    return validPloadLen
#****************************************************************************


#****************************************************************************
# 7
# CONFIGURATION
# Command Class 70
def Configuration(pload):
    validPloadLen = False
    
    # Set or Report
    if pload[0:2] ==  '04' or pload[0:2] ==  '06':
 
        if len(pload)/2 <= 8:
            validPloadLen = True
    # Get
    if pload[0:2] ==  '05':
        # There will be a value after 05 between 0 and 255 (00 and FF)
        if pload[4:6] == '':
            validPloadLen = True
    
    
    return validPloadLen
#****************************************************************************

#****************************************************************************
# 8
# PROTECTION
# Command Class 0x75
def Protection(pload):
    validPloadLen = False
    # Set
    if pload[0:2] == '01':
        if pload[2:4] == '00' or pload[2:4] == '02' or pload[2:4] == '02':
            if pload[4:6] == '':
                validPloadLen = True
    # Get   
    elif pload[0:2] == '02':
        if pload[2:4] == '':
            validPloadLen = True
            
    # Report
    elif pload[0:2] == '03':
        if pload[2:4] == '00' or pload[2:4] == '02' or pload[2:4] == '02':
            if pload[4:6] == '':
                validPloadLen = True                         
    else:
        validPloadLen = False

    
    return validPloadLen
#****************************************************************************

#****************************************************************************
# 9
# ASSOCIATION
# Command Class 85
def Association(pload):
    validPloadLen = False
    
    # Ensure Set, Report
    if pload[0:2] == '01' or pload[0:2] ==  '03':
        if len(pload)/2 <= 10:
            validPloadLen = True
    # Get
    elif pload[0:2] ==  '02':
        if pload[2:4] != '':
            if pload[4:] == '':
                validPloadLen = True
    
    # Remove
    elif pload[0:2] ==  '04':
        if len(pload[2:])/2 <= 4:
            validPloadLen = True 
            
    # GroupingsSet
    elif pload[0:2] ==  '05':
        if pload[2:4] == '':
            validPloadLen = True
    
    # GroupingsReport
    elif pload[0:2] ==  '06':
        validPloadLen = True

    else:
        validPloadLen = False
                   
    return validPloadLen
#****************************************************************************

#****************************************************************************
# 10
# VERSION
# command class 86
def Version(pload, srcID, dstID, ZWVersion, devices_cmdclasses):  
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
                    #print cc
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
            if int(srcID) == int(row[0]):
                for cc in row[1:]:
                    if pload[2:4] == cc:
                        
                        if pload[4:6] == '01' or pload[4:6] == '02':

                            if pload[6:8] == '':
                                validPloadLen = True                   
    else:
        validPloadLen = False

    
    return validPloadLen
#****************************************************************************


#****************************************************************************
# 11
# SECURITY
# Command Class 98
eighty = []
eightyone = []

def Security(pload):
    validPloadLen = False
    
    global eighty
    global eightyone
    
    
    #  Supported Get, SupportedReport, SchemeGet, SchemeReport, 
    # NetworkKeySet, NetworkKeyVerify, SchemeInherit,  
    #  MessageEncapNonceGet
    if (pload[0:2] == '02' or pload[0:2] ==  '03' or pload[0:2] ==  '04' or 
       pload[0:2] ==  '05' or pload[0:2] ==  '06' or pload[0:2] ==  '07' or 
       pload[0:2] ==  '08' or pload[0:2] ==  'c1'):
        if len(pload)/2 <= 2:
            validPloadLen = True
    
    # NonceGet
    elif pload[0:2] ==  '40':
        if pload[2:4] == '':
            validPloadLen = True
    
    # NonceReport - Messages are in pairs or greater.  If a previous 
    # nonce report does not exists, the message is probably a one time inject 
    # and therefore an error
    elif pload[0:2] ==  '80':
          
        if len(eighty)/2 >= 20:
            eighty = []
        
        eighty.append(pload[2:])
        if len(eighty)/2 > 0:
            for nonce_report in eighty:
                if nonce_report == pload[2:]:
                    validPloadLen = True
        
    
    # MessageEncap - Messages are in pairs or greater.  If a previous 
    # messsage encap does not exists, the message is probably a one time 
    # inject and therefore an error
    elif pload[0:2] ==  '81':
        
        if len(eightyone)/2 >= 10:
            eightyone = []

        eightyone.append(pload[2:])
        if len(eightyone) > 0:
            for nonce_report in eightyone:
                if nonce_report == pload[2:]:
                    validPloadLen = True
        
    else:
        validPloadLen = False

    
    return validPloadLen                                                                                                               
#****************************************************************************

#****************************************************************************
# x
# ZWAVE PLUS INFORMATION
# Command class 5e
def Zwaveplusinfo(pload):
    validPloadLen = False
    
    # Get
    if pload[0:2] == '01':
        if pload[2:4] == '':
            validPloadLen = True
    # Report
    elif pload[0:2] == '02':
        # 2 - version, 4 - role, 6 - nodetype, 8.10 - installerIcon, 
        # 12.14 - devicetype
        if len(pload[2:])/2 <= 14:
            validPloadLen = True

    else:
        validPloadLen = False
        
    return validPloadLen 
#****************************************************************************



#****************************************************************************        
# x
# SCENCE ACTIVATION
# Command Class 2b
# 
# INFO from 526:
#   1B    1B         1B             1B               1B           1B
# [cmdCL][cmd][sceneID 00-FF][duration 00-FF][variable 00-FF][variable 00-FF]
#         1B            1B
# [variable 00-FF][variable 00-FF]
def SceneActivation(pload):
    validPloadLen = False
    # Set
    if pload[0:2] == '01':
        if len(pload)/2 <= 6:
            validPloadLen = True     
    else:
        validPloadLen = False

    
    return validPloadLen
#****************************************************************************

#****************************************************************************
# x
# MANUFACTURER SPECIFIC
# Command Class 72
#
# INFO from 526:
#   1B    1B         1B        1B          1B           1B
# [cmdCL][cmd][data 00-FF][data 00-FF][data 00-FF][data 00-FF]
#     1B            1B
# [data 00-FF][data 00-FF]
def ManufacturerSpecific(pload):
    validPloadLen = False
    # Ensure Get or Report
    if pload[0:2] ==  '04' or pload[0:2] ==  '05':                                    
        if len(pload)/2 <= 14:
            validPloadLen = True 
    return validPloadLen
#****************************************************************************
                                  
#**************************************************************************** 
# x                                                                                                                                       
# Command Class 32
def Meter(pload):   
    validPloadLen = False   
    # Get, Report, SupportedGet, SupportedReport, Reset
    if (pload[0:2] == '01' or pload[0:2] ==  '02' or pload[0:2] ==  '04' 
        or pload[0:2] ==  '05'):
            if len(pload)/2 <= 1: 
                validPloadLen = True 
    return validPloadLen
#****************************************************************************
 
#**************************************************************************** 
# x      
# Command Class 26
def SwitchMultilevel(pload):
    validPloadLen = False
    # Set, Get, Report, StartLevelChange, StopLevelChange, 
    # SupportedGet, SupportedReport
    if (pload[0:2] == '01' or pload[0:2] ==  '02' or pload[0:2] ==  '03' or 
        pload[0:2] ==  '04' or pload[0:2] ==  '05' or pload[0:2] ==  '06' or 
        pload[0:2] ==  '07'):
        if len(pload)/2 <= 4:
            validPloadLen = True 
    return validPloadLen
#****************************************************************************

#**************************************************************************** 
# x       
# Command Class 27
def SwitchAll(pload):
    validPloadLen = False
    # Set, Get, Report, On, Off
    if (pload[0:2] == '01' or pload[0:2] ==  '02' or pload[0:2] ==  '03' or
        pload[0:2] ==  '04' or pload[0:2] ==  '05'):
        if len(pload)/2 <= 4:
            validPloadLen = True 
    return validPloadLen
#****************************************************************************

#****************************************************************************
# x
# Command Class 31
def SensorMultilevel(pload):
    validPloadLen = False
    # SupportedGet, SupportedReport, Get, Report
    if (pload[0:2] == '01' or pload[0:2] ==  '02' or pload[0:2] ==  '04' 
        or pload[0:2] ==  '05'):
        if len(pload)/2 <= 14:
            validPloadLen = True                         
    return validPloadLen       
#****************************************************************************


##############################################################################

