#@author Marus Frite
#@category Analysis
#@keybinding
#@menupath
#@toolbar

import binascii
import struct
import jarray


from ghidra.program.model.address import AddressSet

memory = currentProgram.getMemory()
start = memory.getMinAddress()

def getString(adr):
	s = ''
	while memory.getByte(adr) != 0:
		s += chr(memory.getByte(adr))
		adr = adr.add(1)
	return s

class Command():
	def __init__(self, name, nameLen, cmdType, cmdId, paramType):
		self.name = name
		self.nameLen = nameLen
		self.cmdType = cmdType
		self.cmdId = cmdId
		self.paramType = paramType

	def __str__(self):
		if self.cmdType == 0:
			cmdTypeName = 'PARAM'
		elif self.cmdType == 1:
			cmdTypeName = 'PATH'
		elif self.cmdType == 2:
			cmdTypeName = 'CMD'
		elif self.cmdType == 4:
			cmdTypeName = 'TYPE_4'
		paramFlags = []
		if self.paramType == 0:
			paramFlags.append('-')
		else:
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
		if len(self.name) == self.nameLen:
			return "%04x %5s %12s %-12s" % (self.cmdId,cmdTypeName,paramFlags,self.name)
		else:
			return "%04x %8s %12s %-12s" % (self.cmdId,cmdTypeName,paramFlags,'%s(%d)' % (self.name,self.nameLen))

indent = 0

def run():
	def getCommand(cmdAdr):
		global indent
		cmd = jarray.zeros(0x12, "b")
		memory.getBytes(cmdAdr, cmd)
		cmd = bytearray(cmd) # to native Python type
		cmdInfo = struct.unpack('>LBBHBxLL', cmd)
		cmdName = getString(start.add(cmdInfo[0]))
		cmd = Command(cmdName,cmdInfo[1],cmdInfo[2],cmdInfo[3],cmdInfo[4])
		print('%s%s' % (' ' * indent,cmd))
		if cmdInfo[5]: # subcommands
			indent += 2
			getTable(start.add(cmdInfo[5]))
			indent -= 2
		if cmdInfo[6]: # parameter
			indent += 2
			getTable(start.add(cmdInfo[6]))
			indent -= 2
		return cmd

	def getTableHeader(tabAdr):
		tabBase = jarray.zeros(5, "b")
		memory.getBytes(tabAdr, tabBase)
		tabBase = bytearray(tabBase) # to native Python type
		tabBase,tabSize = struct.unpack('>LB', tabBase)
		return start.add(tabBase),tabSize

	def getTable(tableAdr):
		global indent
		tabBase,tabSize = getTableHeader(tableAdr)
		for o in range(tabSize):
			tabEntry = tabBase.add(o * 4)
			if tabEntry >= tableAdr: # this means tabSize is too large for a table
				break # [AUTO,UPPER,UP] is such a case!
			cmdAdr = start.add(memory.getInt(tabEntry))
			cmd = getCommand(cmdAdr)

	getTable(start.add(0x000635da))
	getTable(start.add(0x00063714))

def setPrimaryLabelOnAddr(addr, label, doReplace = False):
	if label.strip() == "":
		return
		
	symbol_table = currentProgram.getSymbolTable()
	symbol = symbol_table.getPrimarySymbol(addr)
	
	if not doReplace and symbol is not None:
		return

	new_symbol = symbol_table.createLabel(addr, label, currentProgram.getGlobalNamespace(), USER_DEFINED)
	new_symbol.setPrimary()
	#new_symbol.setPinned(True)


def setEOLCommentOnAddr(addr, comment, doReplace = False):
	if comment.strip() == "":
		return
	if not doReplace and getEOLComment(addr) is not None:
		return

	setEOLComment(addr, comment)

run()
