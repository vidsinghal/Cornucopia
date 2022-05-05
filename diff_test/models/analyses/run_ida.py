import sys
import os
import subprocess
import time
import json

from bindata import *

IDA_PATH="/mnt/disks/workdisk/ida/"
TIMEOUT=1600

def main():
    if len(sys.argv) != 2:
        print("./<script>.py <binary>")
        sys.exit(-1)

    bin_hash = sys.argv[1].split("/")[-1]
    bin_name = sys.argv[1].split("/")[-2]
    mode = "ida"
    os.system(IDA_PATH+'./idat64 '+ '-A '+ '-c '+ '-S"./analyses/run_ida2.py /tmp/'+ bin_hash +'.txt" '+ sys.argv[1] + " >> ../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_out.txt 2>> ../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_err.txt")
    bin_data = BinData.fromJSON(json.loads(open("/tmp/" + bin_hash + ".txt", "r").read()))
    bin_data.binary_hash = bin_hash
    bin_data.binary_name = bin_name
    os.remove("/tmp/" + bin_hash + '.txt')
    print(bin_data.toJSON())


if __name__ == "__main__":
    main()
