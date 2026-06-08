#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Extract the SCPI cmdId -> handler dispatch from 2400-FIRMWARE.bin.
#
# Both executors switch on gCOMMAND_DATA_PTR->cmdId (word at struct+2) using
# 68k PC-relative 16-bit-offset jump tables:  handler = tableBase + int16(table[idx]).
#
#   SET   (EXECUTE_COMMAND_MAIN  @0x17694): three tables, chained by range:
#     A: base 0x176e4  idx cmdId-0x001  count 0x7e   (cmdId 0x001..0x07e)
#     B: base 0x1c310  idx cmdId-0x081  count 0xce   (cmdId 0x081..0x14e)
#     C: base 0x1fe18  idx cmdId-0x150  count 0x3e   (cmdId 0x150..0x18d)
#   QUERY (EXECUTE_COMMAND_QUERY @0x20f1a): one table:
#     Q: base 0x21156  idx cmdId-0x003  count 0x18a  (cmdId 0x003..0x18c)
#
# A cmdId whose table entry resolves to the table's modal target has no handler
# of that kind (e.g. query-only commands have no SET handler) -> shown as "-".

import struct

data = open('2400-FIRMWARE.bin', 'rb').read()

# ---- cmdId -> SCPI path name (walk the command tables, same struct as dump_scpi) ----
def getString(adr):
    s = ''
    while data[adr] != 0:
        s += chr(data[adr]); adr += 1
    return s

def s16(v): return v - 0x10000 if v & 0x8000 else v

cmd_name = {}   # cmdId -> representative full path

def walk(table_hdr, prefix, seen):
    if table_hdr in seen:
        return
    seen = seen | {table_hdr}
    base, size = struct.unpack('>LB', data[table_hdr:table_hdr+5])
    for o in range(size):
        ent = base + o*4
        if ent >= table_hdr:
            break
        cmdAdr = struct.unpack('>L', data[ent:ent+4])[0]
        nameOff, nameLen, cmdType, cmdId, paramType = struct.unpack('>LBBHB', data[cmdAdr:cmdAdr+9])
        sub5 = struct.unpack('>L', data[cmdAdr+0x0a:cmdAdr+0x0e])[0]
        sub6 = struct.unpack('>L', data[cmdAdr+0x0e:cmdAdr+0x12])[0]
        name = getString(nameOff)
        path = prefix + ':' + name
        if cmdId:
            # keep the shortest/most-canonical path seen for this id
            if cmdId not in cmd_name or len(path) < len(cmd_name[cmdId]):
                cmd_name[cmdId] = path
        if sub5:
            walk(sub5, path, seen)
        if sub6:
            walk(sub6, path, seen)

walk(0x000635da, '', set())   # subsystem tree
walk(0x00063714, '*', set())  # common (*) commands -> names like *:CLS

# ---- jump tables ----
def table_targets(base, k_index_sub, count):
    out = {}
    for i in range(count):
        off = s16(struct.unpack('>H', data[base+i*2:base+i*2+2])[0])
        out[i + k_index_sub] = base + off
    return out

# Each table's "no handler" target is its bhi-default (out-of-range) address.
SET_TABLES = [(0x176e4, 0x001, 0x7e), (0x1c310, 0x081, 0xce), (0x1fe18, 0x150, 0x3e)]
QRY_TABLES = [(0x21156, 0x003, 0x18a)]
SET_DEFAULT = {0x20eea}   # bhi target shared by SET tables A/B/C
QRY_DEFAULT = {0x270ce}   # bhi target of the QUERY table

def build(tables):
    handler = {}
    for base, k, cnt in tables:
        for cid, t in table_targets(base, k, cnt).items():
            handler[cid] = t
    return handler

set_h, set_def = build(SET_TABLES), SET_DEFAULT
qry_h, qry_def = build(QRY_TABLES), QRY_DEFAULT

def fmt(cid, hmap, defs):
    t = hmap.get(cid)
    if t is None or t in defs:
        return '-'
    return '0x%05x' % t

# per-cmdId settability gate (byte table @0x72c2c, checked atop EXECUTE_COMMAND_MAIN):
#   0 = query-only (write -> error 0x20eea), 1 = settable, 2 = special/internal
ATTR_BASE = 0x72c2c
def attr(cid):
    v = data[ATTR_BASE + cid]
    return {0: 'qry-only', 1: 'set+qry', 2: 'special'}.get(v, '0x%02x' % v)

ids = sorted(set(cmd_name) | set(set_h) | set(qry_h))
print('cmdId  W   SET-handler  QUERY-handler  command')
print('-----  --  -----------  -------------  -------')
nset = nqry = 0
for cid in ids:
    s = fmt(cid, set_h, set_def); q = fmt(cid, qry_h, qry_def)
    if s != '-': nset += 1
    if q != '-': nqry += 1
    w = {'qry-only': 'R ', 'set+qry': 'RW', 'special': 'S '}.get(attr(cid), '? ')
    print('0x%04x  %s  %-11s  %-13s  %s' % (cid, w, s, q, cmd_name.get(cid, '?')))
print()
print('total cmdIds: %d   with SET handler: %d   with QUERY handler: %d'
      % (len(ids), nset, nqry))
print('SET default(no-op) handlers: %s' % ', '.join('0x%05x'%x for x in sorted(set_def)))
print('QUERY default(no-op) handler: %s' % ', '.join('0x%05x'%x for x in sorted(qry_def)))
