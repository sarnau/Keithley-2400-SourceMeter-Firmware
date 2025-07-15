#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#!/usr/bin/env python3

import binascii
import struct
import sys

def getString(data,offset):
	s = ''
	while data[offset] != 0:
		s += chr(data[offset])
		offset += 1
	return s

ERROR_EVENT = {
	0:'SYS',
	1:'EE',
	2:'SE',
}

print("""
from ghidra.program.model.data import EnumDataType
import ghidra.program.model.data.DataTypeManager;

dataTypeManager = currentProgram.getDataTypeManager();
 
enum = EnumDataType("ERR_INDEX_ENUM", 4)
""")
data = open('2400-FIRMWARE.bin','rb').read()
BASE = 0x000679b2
for offs in range(143):
	errNo,errEvent,errStr = struct.unpack('>hBxL', data[BASE+offs*8:BASE+offs*8+8])
	errStr = getString(data,errStr)
	#print('#%3d %5d : %3s : "%s"' % (offs,errNo,ERROR_EVENT[errEvent],errStr))
	errStr = 'ERR_INDEX_' + ('%d' % errNo).replace('-','n') + '_' + errStr.replace(' ','_').upper()
	#print(offs, errStr)
	print('enum.add("%s", %d)' % (errStr, offs))
print("""
dataTypeManager.addDataType(enum, None)
""")
