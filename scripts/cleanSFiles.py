import subprocess
import os
import sys
import re


files_folder  = "/home/vidush/Applications/cornucopiaRevisionBinaries/"

for directoryPath, directoryNames, filenames in os.walk(files_folder):
    for filename in filenames:
        if filename.endswith(".s"):

            filePath = os.path.join(directoryPath, filename)
            print("Removing file " + filePath)

            p = subprocess.Popen(["rm", filePath])

            try:
                stdout, stderr= p.communicate()
            except:
                print("Error: could not remove file!")

