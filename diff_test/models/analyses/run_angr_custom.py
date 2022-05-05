#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import angr
import sys

import networkx as nx

from bindata import *

def main():
    if len(sys.argv) != 2:
        print("./<script>.py <binary>")
        sys.exit(-1)

    bin_hash = sys.argv[1].split("/")[-1]
    bin_name = sys.argv[1].split("/")[-2]
    bin_data = BinData(bin_name, bin_hash)
    p = angr.Project(sys.argv[1], load_options={'auto_load_libs': False})

    cfg = p.analyses.CFGFast(normalize=True)
    p.analyses.CompleteCallingConventions(recover_variables=True)
    cfg.normalize()
    cfg.mark_function_alignments()
    for func in cfg.kb.functions.items():
        f = func[1]
        call_sites =  f.get_call_sites()
        if f.alignment:
            continue
        if f.is_syscall:
            continue
        if f.is_plt:
            continue
        if f.size == 0:
            continue
        #f.find_declaration()
        if f.calling_convention != None:
            func_obj = Function(f.addr, f.size, len(f.calling_convention.args), f.returning)
        else:
            func_obj = Function(f.addr, f.size, 0, f.returning)
        #print(f.num_arguments)
        #print(len(f.calling_convention.args))
        mergers = []
        for block in nx.dfs_preorder_nodes(f.graph):
            if block.addr in call_sites:
                mergers.append(block)
            else:
                # get everything from mergers, merge with current block and add
                b_addr = block.addr
                b_size = block.size
                while mergers != []:
                    b = mergers.pop()
                    b_size += b.size
                    b_addr = b.addr

                new_block = BasicBlock(b_addr, b_size)
                block_node = f.get_node(block.addr)
                for edge in f.graph.edges(block_node):
                    new_block.edges.append(edge[1].addr)
                func_obj.basic_blocks[new_block.addr] = new_block

        bin_data.functions[func_obj.addr] = func_obj
        # nx.draw(f.graph, with_labels=True)
        # plt.show()
    print(bin_data.toJSON())

if __name__ == "__main__":
    main()
