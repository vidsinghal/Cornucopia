#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import angr
import sys
import angrmanagement.utils.graph as gh

import networkx as nx

from bindata import *

def main():
    if len(sys.argv) != 3:
        print("./<script>.py <binary> <binary_hash>")
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
        if f.calling_convention != None and f.calling_convention.args != None:
            func_obj = Function(f.addr, f.size, len(f.calling_convention.args), f.returning)
        else:
            func_obj = Function(f.addr, f.size, -1, f.returning)
        #print(f.num_arguments)
        #print(len(f.calling_convention.args))
        mergers = []
        try:
            graph = gh.to_supergraph(f.graph)
        except KeyError:
            continue

        for block in graph.nodes():
            new_block = BasicBlock(block.addr, block.size)
            for node in (graph.successors(block)):
                new_block.edges.append(node.addr)
            #new_block = BasicBlock(b_addr, b_size)
            #block_node = f.get_node(block.addr)
            #for edge in f.graph.edges(block_node):
            #    new_block.edges.append(edge[1].addr)
            func_obj.basic_blocks[new_block.addr] = new_block

        bin_data.functions[func_obj.addr] = func_obj
        # nx.draw(f.graph, with_labels=True)
        # plt.show()
    open("/tmp/" +sys.argv[2] +".atxt", "w").write(bin_data.toJSON())

if __name__ == "__main__":
    main()
