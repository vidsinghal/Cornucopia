#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
import sys
import re
import logging
import multiprocessing_logging
import pebble

logging.basicConfig(filename="progress.log", level=logging.INFO)
logger = logging.getLogger()
multiprocessing_logging.install_mp_handler(logger)

# Edit these to point to the installation directories
TIMEOUT=1800
CLANG_PATH="/workdisk/copa_reeval/clang/llvm-project-llvmorg-5.0.0-rc5/clang/build/bin/clang"
OUTPUT_DIR=""

def mkdr(dir_name):
    if not os.path.isdir(dir_name):
        os.mkdir(dir_name)

def compile_file(input_file):
    source_file_hash = input_file.split("/")[-1]
    prog_name = input_file.split("/")[-2]

    output_path = os.path.join(OUTPUT_DIR, prog_name)
    mkdr(output_path)
    output_path = os.path.join(output_path, source_file_hash.split(".")[0])

    p = subprocess.Popen([CLANG_PATH, "-Wl,--unresolved-symbols=ignore-in-object-files" , input_file,
                          "-o", output_path],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    try:
        stdout, stderr= p.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pgrp = os.getpgid(p.pid)
        os.killpg(pgrp, signal.SIGKILL)
        p.kill()
        stdout, stderr= p.communicate()

    if p.returncode != 0:
        print(p.returncode)
        print(stdout)
        print(stderr)
        return False

    print("[SUCCESS] Compiled file", output_path)
    return True

def main():
    global OUTPUT_DIR
    src_dir = sys.argv[1]
    OUTPUT_DIR = sys.argv[2]

    input_files = []
    for program in os.listdir(src_dir):
        program_path = os.path.join(src_dir, program)
        for variant in os.listdir(program_path):
            f = os.path.join(program_path, variant)
            if os.path.isfile(f):
                input_files.append(f)

    # Test if compile file works
    # sample_input = input_files[0]
    # print(compile_file(sample_input))
    # compile_file()

    with pebble.ProcessPool() as executor:
       try:
           mapFuture = executor.map(compile_file, input_files)
       except KeyboardInterrupt:
           executor.stop()

if __name__ == "__main__":
    main()
                   
