#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This code should be able to do a firmware update via the RS232. At 19200 baud it
# takes a very long time. That said: it failed on me, the flash was written incorrectly,
# despite that there were no error codes, etc. I had to resort to program the Flash by
# pulling the chips out and reprogramming them offline. Warning: in some devices is
# the flash soldered in!

import serial
import time

SERIALPORT = '/dev/cu.usbserial-211240'

def parse_srec_line(line):
    if not line.startswith('S'):
        raise ValueError("Invalid record: does not start with S")
    
    rec_type = line[1]
    byte_count = int(line[2:4], 16)
    
    if rec_type == '1':
        addr_len = 4   # 2 bytes (4 hex digits)
    elif rec_type == '2':
        addr_len = 6   # 3 bytes
    elif rec_type == '3':
        addr_len = 8   # 4 bytes
    elif rec_type in {'5', '7', '8', '9'}:
        # count or start address records
        addr_len = { '9': 4, '8': 6, '7': 8, '5': 4 }[rec_type]
    else:
        raise ValueError(f"Unsupported record type S{rec_type}")
    
    addr = int(line[4:4+addr_len], 16)
    data_end = 4 + addr_len + (byte_count-addr_len//2-1)*2
    data = bytes.fromhex(line[4+addr_len:data_end])
    checksum = int(line[data_end:data_end+2], 16)
    
    # optional: validate checksum
    sum_bytes = byte_count
    for i in range(4, data_end, 2):
        sum_bytes += int(line[i:i+2], 16)
    sum_bytes += checksum
    if (sum_bytes & 0xFF) != 0xFF:
        raise ValueError(f"Checksum mismatch: {line.strip()}")
    
    return rec_type, addr, data

if True:
	ser = serial.Serial(SERIALPORT, 9600)
	ser.write(b':DIAGNOSTIC:KEITHLEY:PROG\n')
	ser.close()
	time.sleep(1)
ser = serial.Serial(SERIALPORT, 19200)
ser.write(b'0042KEITHLEY\n')
with open("./2400-FRP-C34/2400c34.x") as f:
	for line in f:
		line = line.strip() + '\n'
		if line and not line.startswith('S0'):
			inp = ser.read().decode('ascii').strip()
			print(inp)
			if inp == '0':
				rec_type, addr, data = parse_srec_line(line)
				print(f"S{rec_type} Addr: {hex(addr)} Data: {data.hex()}")
				ser.write(line.encode('ascii'))
			elif inp == '3':
				print('BAD S-REC TYPE')
				break
			elif inp == '4':
				print('S-REC CHECKSUM ERROR')
				break
			elif inp == '9':
				print('DONE')
				break
ser.close()
