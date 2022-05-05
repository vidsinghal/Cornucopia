#/usr/bin/env python3
# -*- coding: utf-8 -*-

# script that will compare the data collected by runner
# and report inconsistencies, while at the same time 
# saving crashing/inconsistent input


from models.analyses.bindata import *
from models.runner import get_data

import sys
import json
import networkx as nx
from os.path import exists
import collections


def dump_diff(bin_name, bin_hash, datas):
    for mode in datas:
        file_name = "../diff_fails/" + bin_name + "_" + bin_hash + "_" + mode + ".dump"
        if not exists(file_name):
            open(file_name, "w").write(datas[mode].toJSON())

# We are gonna construct a graph using function start address
# and the function size
def construct_graph(func):
    G = nx.Graph()
    for b in func.basic_blocks:
        block = func.basic_blocks[b]
        block_label = '{:X}'.format(block.addr) + '-' + '{:X}'.format(block.addr+block.size)
        G.add_node(block_label)

    for b in func.basic_blocks:
        block = func.basic_blocks[b]
        block_label = '{:X}'.format(block.addr) + '-' + '{:X}'.format(block.addr+block.size)
        if block.edges != []:
            for edge in block.edges:
                if edge in func.basic_blocks:
                    target_block = func.basic_blocks[edge]
                    target_block_label = '{:X}'.format(target_block.addr) + '-' +'{:X}'.format(target_block.addr + target_block.size)
                    G.add_edge(block_label, target_block_label)
    #print(G)
    return G

def diff_test(bin_path, modes, logger):
    bin_name = bin_path.split("/")[-2]
    bin_hash = bin_path.split("/")[-1]
    datas = {}
    orig_datas = {}
    for mode in modes:
        data = get_data(bin_path, mode, bin_name, bin_hash, logger)
        orig_datas[mode] = data
        if data is not None:
            datas[mode] = BinData.fromJSON(data)
    graphs = {}
    for mode in datas:
        graphs[mode] = {}
        obj = datas[mode]
        for func in obj.functions:
            obj_g = construct_graph(obj.functions[func])
            graphs[mode][obj.functions[func].addr] = obj_g

    '''
    for func in get_user_defined(bin_path):
        print(hex(func))
        nx.draw(graphs["r2"][func], with_labels=True)
        plt.show()
        nx.draw(graphs["angr"][func], with_labels=True)
        plt.show()
    '''
    func_list = get_user_defined(bin_path)    
    #print(func_list)
    if len(func_list) == 0:
        logger.log.info("NO_FUNCS_FOUND:" + bin_name + ":" + bin_hash)
        return
    done = []

    for t1 in modes:
        if t1 not in datas:
            continue
        rest = modes.copy()
        done.append(t1)
        for d in done:
            if d in rest:
                rest.remove(d)
        for t2 in rest:
            if t2 not in datas:
                continue
            for f in func_list:
                perfect_match = True
                dumped = False
                #print(f)
                if f not in datas[t1].functions:
                    logger.info1(bin_name, bin_hash, t1, "FUNCTION_NOT_FOUND", str(f))
                    if not dumped:
                        dump_diff(bin_name, bin_hash, datas)
                        dumped = True
                    continue
                if f not in datas[t2].functions:
                    logger.info1(bin_name, bin_hash, t2, "FUNCTION_NOT_FOUND", str(f))
                    if not dumped:
                        dump_diff(bin_name, bin_hash, datas)
                        dumped = True
                    continue
                if not nx.is_isomorphic(graphs[t1][f], graphs[t2][f]):
                    logger.info2(bin_name, bin_hash, t1, t2, "FUNCTION_GRAPH_MISMATCH", str(f))
                    if not dumped:
                        dump_diff(bin_name, bin_hash, datas)
                        dumped = True
                    perfect_match = False
                if nx.is_isomorphic(graphs[t1][f], graphs[t2][f]):
                    logger.info2(bin_name, bin_hash, t1, t2, "FUNCTION_GRAPH_MATCH", str(f))
                if datas[t1].functions[f].nargs != datas[t2].functions[f].nargs:
                    if func_list[f] != "b'main'":
                        logger.info2(bin_name, bin_hash, t1, t2, "FUNCTION_ARGS_MISMATCH", str(f) + ":" + str(datas[t1].functions[f].nargs) + ":" + str(datas[t2].functions[f].nargs))
                        if not dumped:
                            dump_diff(bin_name, bin_hash, datas)
                        perfect_match = False
                if datas[t1].functions[f].nargs == datas[t2].functions[f].nargs:
                    logger.info2(bin_name, bin_hash, t1, t2, "FUNCTION_GRAPH_MATCH", str(f))
                if perfect_match:
                    logger.info2(bin_name, bin_hash, t1, t2, "PERFECT_MATCH_FUNCTION", str(f))
        done.append(t1)

    logger.log.info("PROCESSED_BINARY:" + bin_name + ":" + bin_hash)
