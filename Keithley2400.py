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
			return "0x%04x %s" % (self.cmdId,self.name)
		elif self.cmdType == 1:
			return ":%s" % (self.name)
		elif self.cmdType == 2:
			return "0x%04x:%s %s" % (self.cmdId,self.name,' | '.join(paramFlags))
		else:
			return "0x%04x:[%s] %s" % (self.cmdId,self.name,' | '.join(paramFlags))

def run():
	def getCommand(cmdAdr):
		cmd = jarray.zeros(0x12, "b")
		memory.getBytes(cmdAdr, cmd)
		cmd = bytearray(cmd) # to native Python type
		cmdInfo = struct.unpack('>LBBHBxLL', cmd)
		cmdName = getString(start.add(cmdInfo[0]))
		parameter = None
		if cmdInfo[5]: # subcommands
			parameter = getTable(start.add(cmdInfo[5]))
		subCommands = None
		if cmdInfo[6]: # parameter
			subCommands = getTable(start.add(cmdInfo[6]))
		return Command(cmdName,cmdInfo[1],cmdInfo[2],cmdInfo[3],cmdInfo[4],parameter,subCommands)

	def getTableHeader(tabAdr):
		tabBase = jarray.zeros(5, "b")
		memory.getBytes(tabAdr, tabBase)
		tabBase = bytearray(tabBase) # to native Python type
		tabBase,tabSize = struct.unpack('>LB', tabBase)
		return start.add(tabBase),tabSize

	def getTable(tableAdr):
		tabBase,tabSize = getTableHeader(tableAdr)
		commands = []
		for o in range(tabSize):
			tabEntry = tabBase.add(o * 4)
			if tabEntry >= tableAdr: # this means tabSize is too large for a table
				break # [AUTO,UPPER,UP] is such a case!
			cmdAdr = start.add(memory.getInt(tabEntry))
			commands.append(getCommand(cmdAdr))
		return commands

	global indent
	indent = 0
	def printCommands(cmdList):
		global indent

		# reversed by name, so we prefer the longer names
		cmdList = reversed(sorted(cmdList, key=lambda x: (x.name)))

		# remove all duplicates
		nlist = []
		idx = 0
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
		cmdList = nlist

		# now sort normally
		cmdList = sorted(cmdList, key=lambda x: (x.cmdId, x.name))
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
					p.append('%d:%s' % (pp,pl[pp]))
			print(' ' * indent + '%s' % cmd + ' %s' % ','.join(p))
			if cmd.subCommands:
				indent += 2
				printCommands(cmd.subCommands)
				indent -= 2

	commands = getTable(start.add(0x000635da))
	printCommands(commands)
	commands = getTable(start.add(0x00063714))
	printCommands(commands)

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
