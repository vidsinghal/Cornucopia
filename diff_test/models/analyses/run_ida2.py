from __future__ import print_function
import idaapi
from idaapi import *

   
import idc
import idaapi
import ida_bytes
import ida_funcs
import ida_search
import ida_struct
import ida_typeinf
import ida_hexrays
import idautils
import ida_ua

import ida_ida
import ida_auto
import ida_loader
import ida_hexrays
import ida_idp
import ida_entry
import ida_kernwin

import idautils
import idc
import sys

from bindata import *

#if len(sys.argv) != 2:
#	print("./<script>.py <binary>")
#	sys.exit(-1)

def init_hexrays():
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    if not decompiler:
        #print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
        return True
    else:
        #print('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False

bin_hash = "p"
bin_name = "p"

bin_data = BinData(bin_name, bin_hash)

f = open(idc.ARGV[1], "w")
ida_auto.auto_wait()
init_hexrays()
basicBlocks = 0
for ea in idautils.Functions():
	func = idaapi.get_func(ea)
	args_num = -1
	try:
		decompiled_func = ida_hexrays.decompile_func(func, None)
		success = True
	except ida_hexrays.DecompilationFailure:
		success = False
	if success:
		try:
			args_num = len(decompiled_func.arguments)
		except AttributeError:
			pass
	func_obj = Function(func.start_ea, func.size(), args_num, func.does_return())
	#f.write(str(func.start_ea) + " " + str(func.size()) + " " + str(args_num) + " " + str(func.does_return()) + "\n")
	
	flowchart = idaapi.FlowChart(func)
	for bb in flowchart:
		new_block = BasicBlock(bb.start_ea, bb.end_ea - bb.start_ea)
		#f.write(str(bb.start_ea) + " "  +str(bb.end_ea - bb.start_ea) + "\n")
		for sc in bb.succs():
			new_block.edges.append(sc.start_ea)
			#f.write("suc " + str(bb.start_ea) + "\n")
		func_obj.basic_blocks[new_block.addr] = new_block
	# basicBlocks += flowchart.size
	bin_data.functions[func_obj.addr] = func_obj

f.write(bin_data.toJSON())

# f.write(str(basicBlocks) + "\n")
f.close()
idc.qexit(0)
