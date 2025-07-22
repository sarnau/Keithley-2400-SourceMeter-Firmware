#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import binascii
import struct
import sys

def getString(data,offset):
	s = ''
	while data[offset] != 0:
		s += chr(data[offset])
		offset += 1
	return s

def verifyChecksum(data, start, size):
	chk = 0x0000
	for i in range(start,start+size-2):
		chk += data[i]
	chk_result = struct.unpack('>H', data[start+size-2:start+size])[0]
	return ((chk + chk_result + 1) & 0xFFFF) == 0x0000

data = open('24LC16B.bin','rb').read()
#print(binascii.hexlify(data))

# All data have a word checksum

# 0x000-0x161 : Calibration Data
# 0x162-0x17F : Calibration Info
# 0x180-0x190 : Serial number (no checksum)
# 0x190-0x199 : Communication Config
# 0x19A-0x1A5 : Hardware Config
# 0x1A6-0x231 : Current Config
# 0x232-0x3CF : CONFIG_0x19E
# 0x3D0-0x3F3 : CONFIG_0x24
# 0x3F4-0x3FF : CONFIG_STR_0x0C
# 0x400-0x7FF : empty (filled with 0xFF)

assert verifyChecksum(data, 0x000, 0x162)
assert verifyChecksum(data, 0x162, 0x01E)
assert verifyChecksum(data, 0x190, 0x00a)
assert verifyChecksum(data, 0x19a, 0x00c)
assert verifyChecksum(data, 0x1A6, 0x08c)
assert verifyChecksum(data, 0x232, 0x19e)
assert verifyChecksum(data, 0x3D0, 0x024)
assert verifyChecksum(data, 0x3F4, 0x00c)

print('Calibration data:')
floats = struct.unpack('>88f', data[0x000:0x160])
calDD = {
	0: '0.2 DCV Range - Sense ',
	1: '2 DCV Range - Sense   ',
	2: '20 DCV Range - Sense  ',
    3: '200 DCV Range - Sense ',

   11: '0.2 DCV Range - Source',
   12: '2 DCV Range - Source  ',
   13: '20 DCV Range - Source ',
   14: '200 DCV Range - Source',
}
for y in range(22):
	fa = floats[y*4:(y+1)*4]
	tt = '#%03x                  ' % (y * 0x10)
	if y in calDD:
		tt = calDD[y]
	print('{:s} : {:e}, {:e}, {:e}, {:e}'.format(tt,fa[0],fa[1],fa[2],fa[3]))

print()
print('Calibration info:')
password,lday,lmonth,lyear,nday,nmonth,nyear,ccount = struct.unpack('>10sBBLBBLL2x', data[0x162:0x162+0x01c])
password = password.decode('ascii')
print('Password : %s' % password)
print('Last Calibration : %d.%d.%d' % (lday,lmonth,lyear))
print('Next Calibration : %d.%d.%d' % (nday,nmonth,nyear))
print('Calibration Count: #%d' % (ccount))

print()
print('Serial number: %s' % getString(data, 0x180))

print()
print("Communication Config")
comMode,SCPI_Adr,RS232_baud,RS232_bits,RS232_parity,RS232_flow,RS232_term,GPIB_mode = struct.unpack('>8B', data[0x190:0x190+0x008])
print('Mode: %s' % ['GPIB','RS232'][comMode])
if comMode == 0:
	print('SCPI Addr: %d' % SCPI_Adr)
	print('GPIB Mode: %s' % ['SCPI','488.1'][GPIB_mode])
else:
	print('RS232 Baudrate: %s' % ['300','600','1200','2400','4800','9600','19200','38400','57600'][RS232_baud])
	print('RS232 Bits: %s' % ['7','8'][RS232_bits])
	if RS232_bits == 0:
		print('RS232 Parity: %s' % ['NONE','ODD','EVEN'][RS232_parity])
	print('RS232 Terminator: %s' % ['<CR>','<CR+LF>','<LF>','<LF+CR>'][RS232_term])
	print('RS232 Flow Control: %s' % ['NONE','XON-XOFF'][RS232_flow])
print()
print("Hardware Config")
posetup,burnInTest,analogBoardRev,digitalBoardRev,powerLineFreq,powerLineFreqAuto,deviceModelId,hw_flags,contactBoardRev = struct.unpack('>B?ccB?BxBc', data[0x19A:0x19A+0x00a])
print('Model : Source Meter %s%s%s' % (['2400','2410','2420','2400 old analog board','2430','2426','2440','2425'][deviceModelId],['',' LV'][(hw_flags & 8)>>3],['',' C'][(hw_flags & 7)!=0]))
print('Board Revisions: Analog %s, Digital %s, Contact %s' % (analogBoardRev.decode('ascii'),digitalBoardRev.decode('ascii'),contactBoardRev.decode('ascii')))
print('Burn-In Test enabled : %s' % burnInTest)
print("Power Line Frequency Detection Automatic : %s" % powerLineFreqAuto)
if not powerLineFreqAuto:
	print("Power Line Frequency: %d Hz" % powerLineFreq)	
print('Power-On Default : %s' % ['DEFAULT #0','DEFAULT #1','DEFAULT #2','DEFAULT #3','DEFAULT #4',None,None,None,None,None,'BENCH','GPIB'][posetup])
print()
