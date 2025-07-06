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

def readSrecord(filename):
	with open(filename) as f:
		d = bytearray()
		for line in f:
			line = line.strip()
			if line:
				rec_type, addr, data = parse_srec_line(line)
				#print(f"S{rec_type} Addr: {hex(addr)} Data: {data.hex()}")
				d += data
		return d

#dd = readSrecord("./2400-FRP-C34/2400c34.x")
msb = readSrecord("./2400-FRP-C34/2400-803C34.x")
lsb = readSrecord("./2400-FRP-C34/2400-804C34.x")
data = bytearray()
for l, h in zip(msb, lsb):
    data.append(h)
    data.append(l)

result = bytearray()
for i in range(0, len(data), 4):
    result.extend(data[i:i+2])
open('2400-FIRMWARE.bin','wb').write(result)
