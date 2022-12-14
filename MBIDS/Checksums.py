###############################################################################
# Checksums.py
#
# Author: Jonathan Fuller
#
# Contains functions to calculate the 8-bit and 16-bit checksums
# Both algorithms are in the ITU-T G.9959 Recommendations

#****************************************************************************
# 8-bit checksum algorithm
# Specified in the ITU-T G.9959 Recommendation
def verify_checksum(packet, ZWaveReq):
    p = bytearray(str(packet))
    p = p[8:-1]
    
    calc_crc = hex(reduce(lambda x, y: x ^ y, p, 0xFF))
    crc_byte = packet[ZWaveReq].get_field('crc').i2repr(packet, packet.crc)

    if (calc_crc == crc_byte): 
        return True
    else: 
        return False
#****************************************************************************


#****************************************************************************
# 16-bit checksum algorithm
# Specified in the ITU-T G.9959 Recommendation
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
#***************************************************************************

###############################################################################
