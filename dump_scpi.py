#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Standalone (non-Ghidra) port of Keithley2400.py: walks the firmware's SCPI
# command-parser tables directly in 2400-FIRMWARE.bin and prints the full
# command tree. The firmware is a flat image loaded at address 0, so every
# Ghidra address equals a file offset.
#
# Command struct (18 bytes, big-endian '>LBBHBxLL'):
#   +0  L  name string offset
#   +4  B  name length (short-form length for SCPI casing)
#   +5  B  cmdType
#   +6  H  cmdId
#   +8  B  paramType bitfield
#   +9  x  pad
#   +A  L  offset of nested table A  (parameters)
#   +E  L  offset of nested table B  (sub-commands)
# Table header (5 bytes '>LB'): entry-array offset, entry count.
# Each entry is a 4-byte big-endian pointer to a Command struct.

import struct

data = open('2400-FIRMWARE.bin', 'rb').read()

def getString(adr):
    s = ''
    while data[adr] != 0:
        s += chr(data[adr])
        adr += 1
    return s

def getInt(adr):
    return struct.unpack('>L', data[adr:adr+4])[0]

class Command():
    def __init__(self, name, nameLen, cmdType, cmdId, paramType, parameter, subCommands):
        self.name = name
        self.nameLen = nameLen
        self.cmdType = cmdType
        self.cmdId = cmdId
        self.paramType = paramType
        self.parameter = parameter
        self.subCommands = subCommands

    def __eq__(self, other):
        if not isinstance(other, Command):
            return NotImplemented
        return self.subCommands == other.subCommands and self.parameter == other.parameter

    def __str__(self):
        paramFlags = []
        if (self.paramType & 1) == 1:
            paramFlags.append('<intvalue>')
        if (self.paramType & 2) == 2:
            paramFlags.append('<str>')
        if (self.paramType & 4) == 4:
            paramFlags.append('<b>')
        if (self.paramType & 8) == 8:
            paramFlags.append('<strlist>')
        if (self.paramType & 0x10) == 0x10:
            paramFlags.append('<numlist>')
        if (self.paramType & 0x20) == 0x20:
            paramFlags.append('0x20')
        if (self.paramType & 0x40) == 0x40:
            paramFlags.append('0x40')
        if (self.paramType & 0x80) == 0x80:
            paramFlags.append('0x80')
        if self.cmdType == 0:
            return "0x%04x %s" % (self.cmdId, self.name)
        elif self.cmdType == 1:
            return ":%s" % (self.name)
        elif self.cmdType == 2:
            return "0x%04x:%s %s" % (self.cmdId, self.name, ' | '.join(paramFlags))
        else:
            return "0x%04x:[%s] %s" % (self.cmdId, self.name, ' | '.join(paramFlags))

def getCommand(cmdAdr):
    cmdInfo = struct.unpack('>LBBHBxLL', data[cmdAdr:cmdAdr+0x12])
    cmdName = getString(cmdInfo[0])
    parameter = getTable(cmdInfo[5]) if cmdInfo[5] else None
    subCommands = getTable(cmdInfo[6]) if cmdInfo[6] else None
    return Command(cmdName, cmdInfo[1], cmdInfo[2], cmdInfo[3], cmdInfo[4], parameter, subCommands)

def getTableHeader(tabAdr):
    tabBase, tabSize = struct.unpack('>LB', data[tabAdr:tabAdr+5])
    return tabBase, tabSize

def getTable(tableAdr):
    tabBase, tabSize = getTableHeader(tableAdr)
    commands = []
    for o in range(tabSize):
        tabEntry = tabBase + o * 4
        if tabEntry >= tableAdr:  # tabSize too large for table (e.g. [AUTO,UPPER,UP])
            break
        commands.append(getCommand(getInt(tabEntry)))
    return commands

indent = 0
def printCommands(cmdList):
    global indent
    cmdList = list(reversed(sorted(cmdList, key=lambda x: x.name)))  # prefer longer names
    # remove duplicates (reconstruct SCPI short/long casing)
    nlist = []
    for cmd in cmdList:
        newElem = True
        for ncmd in nlist:
            if cmd.subCommands and ncmd.subCommands and cmd.subCommands == ncmd.subCommands:
                if ncmd.name.startswith(cmd.name):
                    ncmd.name = cmd.name + ncmd.name.lower()[len(cmd.name):]
                newElem = False
            if cmd.cmdId and ncmd.cmdId and cmd.cmdId == ncmd.cmdId:
                if ncmd.name.startswith(cmd.name):
                    ncmd.name = cmd.name + ncmd.name.lower()[len(cmd.name):]
                newElem = False
            if not newElem:
                break
        if newElem:
            nlist.append(cmd)
    cmdList = sorted(nlist, key=lambda x: (x.cmdId, x.name))
    for cmd in cmdList:
        p = []
        if cmd.parameter:
            pl = {}
            for param in reversed(sorted(cmd.parameter, key=lambda x: x.cmdId)):
                if param.cmdId in pl:
                    pl[param.cmdId] = param.name + pl[param.cmdId].lower()[len(param.name):]
                else:
                    pl[param.cmdId] = param.name
            for pp in pl:
                p.append('%d:%s' % (pp, pl[pp]))
        print(' ' * indent + '%s' % cmd + ' %s' % ','.join(p))
        if cmd.subCommands:
            indent += 2
            printCommands(cmd.subCommands)
            indent -= 2

for hdr in (0x000635da, 0x00063714):
    print('===== root table @ 0x%06x =====' % hdr)
    printCommands(getTable(hdr))
