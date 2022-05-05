
# Display program CFG
#
# @category RandomLLVM.ProgramCFG

# iterate over all functions
from ghidra.program.model.block import BasicBlockModel
#from ghidra.app.script.GhidraScript import getScriptArgs
import ghidra.app.decompiler as decomp
from ghidra.util.task import ConsoleTaskMonitor
import json

args = getScriptArgs()

def get_hex(addr):
    return hex(int(str(addr).replace("L", ""), 16))

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


decompiler = decomp.DecompInterface()
fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)  # True means 'forward'

# dict to store the cfg
bin_data = {}
binary_detail = {}

for func in funcs:
    # print("Basic block details for function '{}':".format(func.getName()))
    decompiler.openProgram(getCurrentProgram())
    d = decompiler.decompileFunction(func, 0, ConsoleTaskMonitor())
    cfunc = d.getHighFunction()
    if cfunc != None:
        decomp_num_args = cfunc.getFunctionPrototype().getNumParams()
    else:
        decomp_num_args = -1

    func_addr = func.getEntryPoint()
    func_detail = {}  # { "addr" : func_addr, "basic_blocks" : {}, "nargs" : 0, "refs" : {}}

    # number of arguments
    func_detail["addr"] = int(str(func_addr), 16)
    func_detail["nargs"] = decomp_num_args
    #func_detail["nargs"] = func.getParameterCount()
    # is returning
    if func.hasNoReturn():
        func_detail["returning"] = False
    else:
        func_detail["returning"] = True

    blockModel = BasicBlockModel(currentProgram)
    monitor = ConsoleTaskMonitor()

    blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)

    # print first block
    # print("\t[*] {} ".format(func.getEntryPoint()))

    basic_blocks_detail = {}
    func_detail["basic_blocks"] = basic_blocks_detail
    func_detail["size"] = 0

    number_of_addresses = 0

    # print any remaining blocks
    while(blocks.hasNext()):
        bb = blocks.next()

        bb_detail = {}
        basic_blocks_detail[str(bb.firstStartAddress)] = bb_detail
        bb_detail["addr"] = int(get_hex(bb.firstStartAddress), 16)
        bb_detail["edges"] = []
        bb_detail["size"] = int(get_hex(bb.getMaxAddress()), 16) - int(get_hex(bb.getMinAddress()), 16)
        func_detail["size"] += bb_detail["size"]

        dest = bb.getDestinations(monitor)
        while(dest.hasNext()):
            dbb = dest.next()
            # For some odd reason `getCodeBlocksContaining()` and `.next()`
            # return the root basic block after CALL instructions (x86). To filter
            # these out, we use `getFunctionAt()` which returns `None` if the address
            # is not the entry point of a function. See:
            # https://github.com/NationalSecurityAgency/ghidra/issues/855
            if not getFunctionAt(dbb.getDestinationAddress()):
                bb_detail["edges"].append(int(get_hex(dbb.getDestinationAddress()).replace("L", ""), 16))
                # print("\t[*] {} ".format(dbb))

    # find all refs
    refs = {}
    func_detail["refs"] = refs
    listing = currentProgram.getListing()
    instructions = listing.getInstructions(func_addr, True)

    for instruction in instructions:
        addr = instruction.getAddress()
        oper = instruction.getMnemonicString()
        if oper == "CALL":
	        
            flows = instruction.getFlows()
            if len(flows) == 1:
                func_call = {}
                refs[get_hex(addr)] = func_call
                target_addr = "0x{}".format(flows[0])
                func_call["call_at"] = get_hex(addr)
                func_call["call_to"] = get_hex(getAddress(target_addr))

    binary_detail[str(func_addr)] = func_detail

bin_data["binary_name"] = "none"
bin_data["binary_hash"] = "none"
bin_data["functions"] = binary_detail

open("/tmp/"+args[0]+".gtxt", "w").write(json.dumps(bin_data, indent=2, sort_keys=True))
