#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# High level script that runs the
# differential analysis tests

import argparse
import os
import re
import pebble
import time
from functools import partial


from models.diff_test import diff_test
from models.diff_logger import Logger

blklist = ["idb","nam", "id0", "id1", "til", "id2", "i64", "c"]

def get_bins(bin_dir, processed):
    binaries = []
    for subdir, dirs, files in os.walk(bin_dir):
        for f in files:
            if f in processed:
                continue
            if f.split(".")[-1] not in blklist:
                binary = str(subdir) + "/" + str(f)
                binaries.append(binary)

    return binaries

def mkdr(dir_name):
    if not os.path.isdir(dir_name):
        os.mkdir(dir_name)

def read_file(path):
    with open(path, "r") as fd:
        data = fd.read()
        return data

def prep_dirs():
    mkdr("diff_fails")
    mkdr("crashes")

def main():
    parser = argparse.ArgumentParser(description="""Script to run various
        differential analysis tests on binaries""")

    parser.add_argument('bin_dir', metavar='binaires_directory',
            help='Directory pointing to all the binaries to be tested')

    parser.add_argument('-r', '--resume', action='store_true')

    args = parser.parse_args()
    prep_dirs()
    logger = Logger()

    input_bins = []
    progress = read_file("progress.log")
    processed_bins = []
    result = re.findall('INFO:root:PROCESSED_BINARY:.*', progress)
    for i in result:
        processed_bins.append(i.split(":")[-1])

    for subdir, dirs, files in os.walk(args.bin_dir):
        for f in files:
            if f in processed_bins:
                continue
            input_bins.append(subdir + "/" + f)

    totalBinaries = get_bins(args.bin_dir, processed_bins)
    # run all the tests in parallel
    with pebble.ProcessPool(max_workers=8) as executor:
        differential_tester = partial(diff_test, modes=["r2", "ida","angr", "ghidra"], logger=logger)
        try:
            executor.map(differential_tester, totalBinaries)
        except KeyboardInterrupt:
            executor.stop()

        

if __name__ == "__main__":
    main()
