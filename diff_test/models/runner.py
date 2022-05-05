#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# run the various analyses, check for 
# crashes or erros in cfg generation/ 
# collection of BinData

# collect json output from tools
# deserialise and send to diff_test for comparison

import sys
import subprocess
import os
import json
import signal
import psutil
import uuid

#from diff_logger import Logger
from models.analyses.bindata import BinData


TIMEOUT=600
IDA_PATH="/workdisk/tools/ida/"
GHIDRA_PATH="/workdisk/anon/ghidra/build/dist/ghidra_10.2_DEV"

def get_data_ida(bin_path, bin_name, bin_hash, logger):
    mode = "ida"
    p = subprocess.Popen(IDA_PATH+'idat -A -c -S"./analyses/run_ida2.py /tmp/' + bin_hash + '.txt" ' + "../" +bin_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid, shell=True)

    try:
        stdout, stderr = p.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pgrp = os.getpgid(p.pid)
        os.killpg(pgrp, signal.SIGKILL)
        p.kill()
        logger.log.info("TOOL_TIMEOUT" + ":" + mode + ":" + bin_name + ":" + bin_hash)
        return None

    if p.returncode != 0:
        logger.log.info("TOOL_CRASH" + ":" + mode + ":" + bin_name + ":" + bin_hash + ":" + "ERR_CODE" + ":" + str(p.returncode))
        open("../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_out.txt", "wb").write(stdout)
        open("../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_err.txt", "wb").write(stderr)
        return None
    try:
        bin_data = BinData.fromJSON(json.loads(open("/tmp/" + bin_hash + ".txt", "r").read()))
        bin_data.binary_hash = bin_hash
        bin_data.binary_name = bin_name
        os.remove("/tmp/" + bin_hash + '.txt')
        return json.loads(bin_data.toJSON())
    except FileNotFoundError:
        logger.log.info("NO_OUTPUT" + ":" + mode + ":" + bin_name + ":" + bin_hash + ":" + "ERR_CODE" + ":" + str(p.returncode))
        return None


def get_data_ghidra(bin_path, bin_name, bin_hash, logger):
    mode = "ghidra"
    p = subprocess.Popen(GHIDRA_PATH+'/support/analyzeHeadless . proj' + str(uuid.uuid4())+ ' -import ' + "../"  + bin_path + ' -overwrite -max-cpu 1 -postscript ./analyses/run_ghidra2.py ' + bin_hash, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid, shell=True)

    try:
        stdout, stderr = p.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pgrp = os.getpgid(p.pid)
        os.killpg(pgrp, signal.SIGKILL)
        p.kill()
        logger.log.info("TOOL_TIMEOUT" + ":" + mode + ":" + bin_name + ":" + bin_hash)
        return None

    if p.returncode != 0:
        logger.log.info("TOOL_CRASH" + ":" + mode + ":" + bin_name + ":" + bin_hash + ":" + "ERR_CODE" + ":" + str(p.returncode))
        open("../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_out.txt", "wb").write(stdout)
        open("../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_err.txt", "wb").write(stderr)
        return None
    try:
        bin_data = BinData.fromJSON(json.loads(open("/tmp/" + bin_hash + ".gtxt", "r").read()))
        bin_data.binary_hash = bin_hash
        bin_data.binary_name = bin_name
        os.remove("/tmp/" + bin_hash + '.gtxt')
        return json.loads(bin_data.toJSON())
    except FileNotFoundError:
        logger.log.info("NO_OUTPUT" + ":" + mode + ":" + bin_name + ":" + bin_hash + ":" + "ERR_CODE" + ":" + str(p.returncode))
        return None

def get_data_angr(bin_path, bin_name, bin_hash, logger):
    mode = "angr"
    p = subprocess.Popen(["python3.8", "analyses/run_" + mode + ".py", 
        "../" + bin_path, bin_hash], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)

    try:
        stdout, stderr = p.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pgrp = os.getpgid(p.pid)
        os.killpg(pgrp, signal.SIGKILL)
        p.kill()
        logger.log.info("TOOL_TIMEOUT" + ":" + mode + ":" + bin_name + ":" + bin_hash)
        return None

    if p.returncode != 0:
        logger.log.info("TOOL_CRASH" + ":" + mode + ":" + bin_name + ":" + bin_hash + ":" + "ERR_CODE" + ":" + str(p.returncode))
        open("../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_out.txt", "wb").write(stdout)
        open("../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_err.txt", "wb").write(stderr)
        return None
    try:
        bin_data = BinData.fromJSON(json.loads(open("/tmp/" + bin_hash + ".atxt", "r").read()))
        bin_data.binary_hash = bin_hash
        bin_data.binary_name = bin_name
        os.remove("/tmp/" + bin_hash + '.atxt')
        return json.loads(bin_data.toJSON())
    except FileNotFoundError:
        logger.log.info("NO_OUTPUT" + ":" + mode + ":" + bin_name + ":" + bin_hash + ":" + "ERR_CODE" + ":" + str(p.returncode))
        return None

def get_data(bin_path, mode, bin_name, bin_hash, logger):
    os.chdir(os.path.dirname(__file__))

    if mode == "ida":
        return get_data_ida(bin_path, bin_name, bin_hash, logger)

    if mode == "ghidra":
        return get_data_ghidra(bin_path, bin_name, bin_hash, logger)

    if mode == "angr":
        return get_data_angr(bin_path, bin_name, bin_hash, logger)
    # make sure we are in same dir where the script is.
    # we use subprocess here so that mem limit/ seg fualts don't kill everything 
    p = subprocess.Popen(["python3.8", "analyses/run_" + mode + ".py", 
        "../" + bin_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)

    try:
        stdout, stderr = p.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pgrp = os.getpgid(p.pid)
        os.killpg(pgrp, signal.SIGKILL)
        p.kill()
        logger.log.info("TOOL_TIMEOUT" + ":" + mode + ":" + bin_name + ":" + bin_hash)
        return None


    if p.returncode != 0:
        try:
            return json.loads(stdout)
        except:
            logger.log.info("TOOL_CRASH" + ":" + mode + ":" + bin_name + ":" + bin_hash + ":" + "ERR_CODE" + ":" + str(p.returncode))
            open("../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_out.txt", "wb").write(stdout)
            open("../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_err.txt", "wb").write(stderr)
            return None

    try:
        return json.loads(stdout)
    except:
        print(stdout)
        logger.log.info("NO_OUTPUT" + ":" + mode + ":" + bin_name + ":" + bin_hash + ":" + "ERR_CODE" + ":" + str(p.returncode))
        return None

if sys.argv[1] == "--test":
    bin_path = sys.argv[2]
    bin_name = bin_path.split("/")[-2]
    bin_hash = bin_path.split("/")[-1]
    logger = Logger()
    print(get_data_ghidra(bin_path, bin_name, bin_hash, logger))
