#@author claude
#@category Keithley2400
#@menupath Tools.Keithley.Sweep code-ptr calls
#
# Decompiler-wide sweep for residual "(code *)" indirect-call casts.
#
# Finds every function that contains an indirect (computed) CALL instruction,
# decompiles it, and prints any decompiled C line that still shows a
# "(code *" cast -- i.e. an indirect call through a pointer that is NOT yet
# typed as a function pointer. A clean firmware prints zero CAST lines.
#
# Run from Ghidra Script Manager against 2400-FIRMWARE.bin.

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

prog = currentProgram
listing = prog.getListing()

# 1) Gather functions containing >=1 indirect/computed call instruction.
ind_funcs = {}          # entryPoint(str) -> Function
ind_insn_count = 0
insns = listing.getInstructions(True)
while insns.hasNext():
    insn = insns.next()
    ft = insn.getFlowType()
    if ft is not None and ft.isCall() and ft.isComputed():
        ind_insn_count += 1
        f = listing.getFunctionContaining(insn.getAddress())
        if f is not None:
            ind_funcs[str(f.getEntryPoint())] = f

print("Indirect-call instructions: %d in %d functions" %
      (ind_insn_count, len(ind_funcs)))

# 2) Decompile each and scan the C for "(code *".
dec = DecompInterface()
dec.openProgram(prog)
monitor = ConsoleTaskMonitor()

funcs_with_cast = 0
cast_sites = 0
for ep in sorted(ind_funcs.keys()):
    f = ind_funcs[ep]
    res = dec.decompileFunction(f, 60, monitor)
    if res is None or not res.decompileCompleted():
        print("  [DECOMP-FAIL] %s @ %s" % (f.getName(), ep))
        continue
    c = res.getDecompiledFunction().getC()
    if "(code *" in c:
        funcs_with_cast += 1
        for line in c.split("\n"):
            if "(code *" in line:
                cast_sites += 1
                print("  CAST  %s @ %s :: %s" % (f.getName(), ep, line.strip()))

print("----")
print("Functions still showing (code *) cast: %d" % funcs_with_cast)
print("Total (code *) cast lines: %d" % cast_sites)
if funcs_with_cast == 0:
    print("CLEAN: no residual code-pointer indirect calls.")
