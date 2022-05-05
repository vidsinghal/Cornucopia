#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# runs r2 on provided binary and 
# outputs data in BinData json

import sys
import r2pipe
import json
import operator

from bindata import *

def main():
    if len(sys.argv) != 2:
        print("./<script>.py <binary>")
        sys.exit(-1)

    r2 = r2pipe.open(sys.argv[1])
    bin_hash = sys.argv[1].split("/")[-1]
    bin_name = sys.argv[1].split("/")[-2]
    bin_data = BinData(bin_name, bin_hash)
    # standard automatic analysis
    auto_analysis = r2.cmd('aaa')
    r2.cmd('e scr.interactive=0')
    # list functions recongnized
    function_list = ""
    while(len(function_list) == 0):
        function_list = r2.cmd('afllj')
    function_list = json.loads(function_list)
    for func in function_list:
        if "nargs" in func:
            func_obj = Function(func["offset"], func["size"], func["nargs"], not func["noreturn"])
        else:
            func_obj = Function(func["offset"], func["size"], -1, not func["noreturn"])
        basic_blocks = json.loads(r2.cmd('afbj @' + str(func["offset"])))
        for block in basic_blocks:
            try:
                new_block = BasicBlock(block["addr"], block["size"])
            except KeyError:
                continue
            if "jump" in block:
                new_block.edges.append(block["jump"])
            if "fail" in block:
                new_block.edges.append(block["fail"])
            if "switch_op" in block:
                for case in (block["switch_op"]["cases"]):
                    new_block.edges.append(case["jump"])
                
            func_obj.basic_blocks[new_block.addr] = new_block


        if "callrefs" in func:
            for refs in func["callrefs"]:
                if refs["type"] == "CALL":
                    func_obj.refs[refs["at"]] = FunctionRef(refs["addr"], refs["at"])
        bin_data.functions[func_obj.addr] = func_obj
    print(bin_data.toJSON())

if __name__ == "__main__":
    main()
