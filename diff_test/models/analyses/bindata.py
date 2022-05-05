#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# basic structure of binary data
# to be collected from various tools

import json
import subprocess


TIMEOUT = 180


class BasicBlock(object):
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size
        self.edges = []

class Function(object):
    def __init__(self, addr, size, nargs, returning):
        self.addr = addr
        self.size = size
        self.nargs = nargs
        self.returning = returning 
        self.refs = {}
        self.basic_blocks = {}

class FunctionRef(object):
    def __init__(self, call_to, call_at):
        self.call_to = call_to
        self.call_at = call_at

class BinData(object):
    def __init__(self, binary_name, binary_hash):
        self.binary_name = binary_name
        self.binary_hash = binary_hash
        self.functions = {}
        # Data that we collect:
        # 1. no of functions
        # 2. no of basic blocks in said functions 
        # 3. boundaries of said functions 
        # 4. calling conventions 
        #       a. function calls
        #       b. arguments of said function call
        #       c. return value of said function

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
                sort_keys=True, indent=4)

    def fromJSON(data):
        bin_data = BinData(data["binary_name"], data["binary_hash"])
        func_list = data["functions"]
        for f in func_list:
            func = func_list[f]
            f = Function(func["addr"], func["size"], func["nargs"], func["returning"])
            refs_list = func["refs"] 
            for rd in refs_list:
                ref_d = refs_list[rd]
                f.refs[ref_d["call_at"]] = FunctionRef(ref_d["call_to"], ref_d["call_at"])
            blocks_list = func["basic_blocks"]
            for bd in blocks_list:
                block_d = blocks_list[bd]
                new_block = BasicBlock(block_d["addr"], block_d["size"])
                new_block.edges = block_d["edges"]
                f.basic_blocks[new_block.addr] = new_block
            bin_data.functions[f.addr] = f
        return bin_data


def get_user_defined(binary):
    bin_name = binary.split("/")[-2]
    bin_hash = binary.split("/")[-1]
    p = subprocess.Popen(["nm", "../unstripped/"  + bin_name + "/" + bin_hash], 
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    user_defined = {}
    try:
        stdout, stderr= p.communicate(timeout=TIMEOUT)
        for l in stdout.splitlines():
            l = l.split()
            if l[1] == b"T":
                if not l[2].startswith(b"_"):
                    user_defined[int(l[0], 16)] = str(l[2])
    except subprocess.TimeoutExpired:
        p.kill()
        stdout, stderr= p.communicate()
    return user_defined
