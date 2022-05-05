import sys
import os
import subprocess
import time
import json
import uuid

from bindata import *

GHIDRA_PATH="/mnt/disks/workdisk/ghidra_10.1_DEV/"
#GHIDRA_PATH="/workdisk/anon/stuff/ghidra_10.0.4_PUBLIC/"
TIMEOUT=1600

def main():
    if len(sys.argv) != 2:
        print("./<script>.py <binary>")
        sys.exit(-1)
	
    bin_hash = sys.argv[1].split("/")[-1]
    bin_name = sys.argv[1].split("/")[-2]
    mode = "ghidra"
    os.system(GHIDRA_PATH+'/support/analyzeHeadless . proj' + str(uuid.uuid1())  + ' -import ' + sys.argv[1] + ' -overwrite -postscript ./analyses/run_ghidra2.py ' + bin_hash + " >> ../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_out.txt 2>> ../crashes/" + bin_name + "_" + bin_hash + "_" + mode + "_err.txt")
    #os.system(GHIDRA_PATH+'/support/analyzeHeadless . ' + bin_hash +' -import ' + sys.argv[1] + ' -overwrite -postscript ./analyses/run_ghidra2.py ' + bin_hash)  
    bin_data = BinData.fromJSON(json.loads(open("/tmp/" + bin_hash + ".gtxt", "r").read()))
    bin_data.binary_hash = bin_hash
    bin_data.binary_name = bin_name
    os.remove("/tmp/" + bin_hash + '.gtxt')
    print(bin_data.toJSON())



if __name__ == "__main__":
    main()
