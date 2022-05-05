import os
import elftools
import pickle
from pathlib import Path
from models.analyses.bindata import *
from elftools.elf.elffile import ELFFile

def get_funcs(binary):
    elffile = ELFFile(open(binary, "rb"))
    if not elffile.has_dwarf_info():
        print('  file has no DWARF info')
        return hash_list, architectureName

    dwarfinfo = elffile.get_dwarf_info()
    funcs = {}
    try:
        for CU in dwarfinfo.iter_CUs():
            try:
                for DIE in CU.iter_DIEs():
                    try:
                        if DIE.tag == 'DW_TAG_subprogram':
                            addr = DIE.attributes['DW_AT_low_pc'].value
                            size = DIE.attributes['DW_AT_high_pc'].value
                            funcs[addr] = {"size": size, "nargs" : 0}
                        if DIE.tag == 'DW_TAG_formal_parameter':
                            funcs[addr]["nargs"] += 1 
                    except KeyError:
                        continue
            except:
                continue
    except AssertionError:
        return None
    except elftools.common.exceptions.DWARFError:
        return None
    return funcs

data_dir_prefix = "final_diff_results"

archs = ["x32", "x64", "arm", "mips"]
tools = ["angr", "ghidra", "ida", "r2"]

candidates = {}
total_binaries_dumped = 0
binaries_with_gt = 0

tFm = 0
tFs = {"angr": 0, "ghidra": 0, "ida": 0, "r2": 0}
tSa = 0
for arch in archs:
    Fm = set()
    Fs = {"angr": set(), "ghidra": set(), "ida": set(), "r2": set()}
    Sa = set()
    cc_agreeing = {}
    cc_disagreeing = {}
    total_funcs = set()
    funcs_not_found = set()
    tools_disagree = 0
    if arch not in candidates:
        candidates[arch] = {}
    diff_data_path = os.path.join(data_dir_prefix, arch, "diff_fails")
    diff_dumps_list = Path(diff_data_path).glob('*.dump')
    for dump_file in diff_dumps_list:
        filename = os.path.basename(dump_file)
        # I made the mistake of using underscore as the separator in filenames
        # we are gonna have to do some tricky stuff to get the binary name and 
        # the variant hash separated properly
        filename = filename.split("_")
        tool_name = filename[-1].split(".")[0]
        variant_hash = filename[-2]
        bin_name = "_".join(filename[0:-2])
        if bin_name not in candidates:
            candidates[arch][bin_name] = {}
        if variant_hash not in candidates[arch][bin_name]:
            candidates[arch][bin_name][variant_hash] = {}
        candidates[arch][bin_name][variant_hash][tool_name] = {}
        total_binaries_dumped += 1
    

        tool_specific_dump =  BinData.fromJSON(json.loads(open(dump_file, "r").read()))
        
        for func in tool_specific_dump.functions:
            nargs = tool_specific_dump.functions[func].nargs
            func_size = tool_specific_dump.functions[func].size
            func_detail = {"size": func_size, "nargs": nargs}
            candidates[arch][bin_name][variant_hash][tool_name][func] = func_detail

        # We should get the ground truth for this particular binary from 
        # the dwarf information here, then check with the content fom each 
        # of the tools below

        binary_path = os.path.join(data_dir_prefix, arch, "unstripped", bin_name, variant_hash)
        funcs_gt = get_funcs(binary_path)
        candidates[arch][bin_name][variant_hash]["gt"] = funcs_gt

        # separate code from below this point and add 
        # resume functionality from data dump if available?

        if funcs_gt != None and len(funcs_gt) != 0:
            binaries_with_gt += 1
            for tool in tools:

                if tool not in candidates[arch][bin_name][variant_hash]:
                    funcs = {}
                else:
                    funcs = candidates[arch][bin_name][variant_hash][tool]

                for func_addr in funcs_gt:
                    func_uid = ":".join([bin_name, variant_hash, str(func_addr)])
                    if func_addr not in funcs:
                        # do we count these too?
                        # cmp_func_size = -1
                        continue

                    cmp_func_size = funcs[func_addr]["nargs"]
                        #continue

                    total_funcs.add(func_uid)
                    if func_uid not in cc_agreeing:
                        cc_agreeing[func_uid] = []
                    # cmp_func_size = funcs[func_addr]["nargs"]
                    if cmp_func_size == funcs_gt[func_addr]["nargs"]:
                        cc_agreeing[func_uid].append(tool)
                    # else:
                    #     if func_uid not in cc_agreeing:
                    #         cc_agreeing[func_uid] = []

        #if len(total_funcs) > 200:
        #    break

    #do the arch specific additions here by iterating though cc_agreeeing here ig
    # print(cc_agreeing)
    for fuid in cc_agreeing:
        l = len(cc_agreeing[fuid])
        if l == 4:
            Sa.add(fuid)
        elif l == 3:
            # define disagreeing tool here
            disagreeing_tool = list(set(tools) - set(cc_agreeing[fuid]))
            Fs[disagreeing_tool[0]].add(fuid)
        else:
            Fm.add(fuid)

    tf = len(total_funcs)
    print("For Arch : {arch}".format(arch=arch))
    for tool in tools:
        print("Fs {tool} : {no} {p}".format(tool=tool, no=len(Fs[tool]), p=(len(Fs[tool])/tf)*100))
    print("Fm : {no} {p}".format(no=len(Fm), p=(len(Fm)/tf)*100))
    print("Sa : {no} {p}".format(no=len(Sa), p=(len(Sa)/tf)*100))
    print("Total Funcs: {tf}".format(tf=len(total_funcs)))

    #we also print the tool wise inaccuracies
    Iangr = 0
    Ighidra = 0
    Iida = 0
    Ir2 = 0
    for fuid in cc_agreeing:
        if "angr" not in cc_agreeing[fuid]:
            Iangr += 1
        if "ghidra" not in cc_agreeing[fuid]:
            Ighidra += 1
        if "ida" not in cc_agreeing[fuid]:
            Iida += 1
        if "r2" not in cc_agreeing[fuid]:
            Ir2 += 1

    print("angr : {no}".format(no=Iangr))
    print("ghidra : {no}".format(no=Ighidra))
    print("ida : {no}".format(no=Iida))
    print("r2 : {no}".format(no=Ir2))
        
        
# we be dumping everything we collect so far
with open("cc_gt_data.dump", "wb") as fp:
    pickle.dump(candidates, fp)
                    

print("Total binaries dumped:", total_binaries_dumped)
print("Binareis with ground truth:", binaries_with_gt)
print("pyelftools errors {err}".format(err=total_binaries_dumped-binaries_with_gt))