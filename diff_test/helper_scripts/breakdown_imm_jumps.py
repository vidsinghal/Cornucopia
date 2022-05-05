
import pickle
import os
from models.analyses.bindata import *

backup_prefix = "bkup_apr_21"
final_results_prefix = "final_diff_results"
archs = ["x32", "x64", "arm", "mips"]

# First we get the rep instructions for x32, x64 ARM

# lets open the detailed analysis pickle dump for x64 angr:
arch = "mips"
tool = "angr"
var_tool = "r2"
pickle_dump_path = os.path.join(backup_prefix, "detailed_data_" + arch + "_" + tool + ".dump")
diff_dump_path = os.path.join(final_results_prefix,arch,"diff_fails")
funcs_with_rep = set()
with open(pickle_dump_path, "rb") as fp:
        detailed_data = pickle.load(fp)

        # we are specifically looking for the errors in no. of basic blocks
        bb_no_mismatch = detailed_data["BB_no_mismatch"]
        # print(bb_no_mismatch)

        # now we get enough info to get dump
        for f in bb_no_mismatch:
            binary, bin_hash, func_addr = f.split(":")
            # print(binary, bin_hash, func_addr)

            # now we get the dump:
            data_path = os.path.join(diff_dump_path, binary + "_" + bin_hash + "_" + tool + ".dump")
            var_data_path = os.path.join(diff_dump_path, binary + "_" + bin_hash + "_" + var_tool + ".dump")
            if os.path.exists(data_path):
                #data_restored = BinData.fromJSON(json.loads(open(data_path, "r").read()))
                var_data_restored = BinData.fromJSON(json.loads(open(var_data_path, "r").read()))
                # we now get the basic blocks of this function:
                try:
                    bbs = var_data_restored.functions[int(func_addr)].basic_blocks
                    # Write your hackish case detection stuff here!
                    for bb in bbs:
                        if bbs[bb].size == 2: # Should be changed to 4 for arm and mips
                            if (bbs[bb].addr+bbs[bb].size) in bbs[bb].edges:
                                funcs_with_rep.add(f)
                except KeyError:
                    print("DUMP_FOR_FUNCTION_NOT_FOUND, POSSIBLE TOOL FAILURE") 
            else:
                print("DUMP_NOT_FOUND, POSSIBLE TOOL FAILURE : {f}".format(f=f))
        funcs_no_rep = set(bb_no_mismatch) - funcs_with_rep 
                
print(funcs_no_rep)
print(len(funcs_with_rep))
