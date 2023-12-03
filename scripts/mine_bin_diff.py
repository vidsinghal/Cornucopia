import pandas as pd
import matplotlib.pyplot as plt
from pandas.core.base import DataError
import numpy as np
from datetime import datetime
import os
import re
import statistics
from statistics import mean
from statistics import median

Optimizations = ["O0", "O1", "O2", "O3"]

BaseFolder = "/home/vidush/Applications/bindiff_new/"

orig_sources = [
"openssl",
"482.sphinx3",
"453.povray",
"445.gobmk",
"464.h264ref",
"483.xalancbmk",
"429.mcf",
"433.milc",
"447.dealII",
"470.lbm",
"450.soplex",
"401.bzip2",
"456.hmmer",
"400.perlbench",
"462.libquantum",
"471.omnetpp",
"444.namd"  ,
"473.astar" ,
"458.sjeng" ,
"coreutils" ]

#"["         , "basenc" , "chown"   , "csplit"   ,  "dir"       ,  "env"    ,  "fmt"    ,  "id"      ,  "ln"      ,  "mkfifo" ,  "nl"     ,  "paste"   ,  "printf"   ,  "rm"      ,  "sha224sum" ,  "shuf"  ,  "stty" ,  "tee"     ,  "true"     ,  "unexpand" ,  "vdir"   ,  "yes" ,
 #"b2sum"    , "cat"    ,  "chroot" ,  "cut"     ,  "dircolors" ,  "expand" ,  "fold"   ,  "install" ,  "logname" ,  "mknod"  ,  "nohup"  ,  "pathchk" ,  "ptx"      ,  "rmdir"   ,  "sha256sum" ,  "sleep" ,  "sum"  ,  "test"    ,  "truncate" ,  "uniq"     ,  "wc"     ,
 #"base32"   , "chcon"  ,  "cksum"  ,  "date"    ,  "dirname"   ,  "expr"   ,  "groups" ,  "join"    ,  "ls"      ,  "mktemp" ,  "nproc"  ,  "pinky"   ,  "pwd"      ,  "runcon"  ,  "sha384sum" ,  "sort"  ,  "sync" ,  "timeout" ,  "tsort"    ,  "unlink"   ,  "who"    ,
 #"base64"   , "chgrp"  ,  "comm"   ,  "dd"      ,  "du"        ,  "factor" ,  "head"   ,  "kill"    ,  "md5sum"  ,  "mv"     ,  "numfmt" ,  "pr"      ,  "readlink" ,  "seq"     ,  "sha512sum" ,  "split" ,  "tac"  ,  "touch"   ,  "tty"      ,  "uptime"   ,  "whoami" ,
 #"basename" , "chmod"  ,  "cp"     ,  "df"      ,  "echo"      ,  "false"  ,  "hostid" ,  "link"    ,  "mkdir"   ,  "nice"   ,  "od"     ,  "printenv",  "realpath" ,  "sha1sum" ,  "shred"     ,  "stat"  ,  "tail" ,  "tr"      ,  "uname"    ,  "users" ]

orig_sources = ["/" + x + "/" for x in orig_sources]

#print(orig_sources)

Folder = BaseFolder

DATA = {}

#sub_folders = ["/bintuner/",  "/cc_bintuner/",  "/cc_parallel/", "/cc_single/"]
sub_folders = ["/bintuner/",  "/cc_bintuner/", "/cc_single/"]


data_coreutils = [{}, {}, {}, {}]
data_openssl   = [{}, {}, {}, {}]
data_spec      = [{}, {}, {}, {}]


class fileScores:
    def __init__(self, filename):
        self.name = filename
        self.O0 = 0
        self.O1 = 0
        self.O2 = 0
        self.O3 = 0
        
    def setO0(self, O0):
        self.O0 = O0
    
    def setO1(self, O1):
        self.O1 = O1
        
    def setO2(self, O2):
        self.O2 = O2
        
    def setO3(self, O3):
        self.O3 = O3
        
    def getO0(self):
        return self.O0
    
    def getO1(self):
        return self.O1
        
    def getO2(self):
        return self.O2
        
    def getO3(self):
        return self.O3
    
    def getName(self):
        return self.name
        
    
COUNTER = 0

for basedir, dirs, files in os.walk(Folder):
    
    if len(files) != 0:
        
        for file in files:            
            #print(basedir)
            
            #add check to see if source is actually valid or not  
            check_dir = basedir+"/"        
            check_valid_source = [True if x in check_dir else False for x in orig_sources]
            #print(check_dir)
            if (any(check_valid_source)):
            
                if ".results" in file:
                    
                    #COUNTER += 1
                    #print("The Counter val is: " + str(COUNTER))
                    #if COUNTER > 100: 
                        #break
                    
                    #get the file path
                    log_file = str(basedir) + "/" + str(file)
                    f = open(log_file, "r")
                    log_lines = f.readlines()
                
                    if len(log_lines) == 0:
                        continue
                    
                    #get all the log lines
                    log_lines = [line.rstrip() for line in log_lines]
                    #print(log_lines)
                    
                    #opt level
                    optimization = log_lines[0]
                    #print(optimization)
                    
                    #file hash
                    fileHash   = log_lines[1]
                    #print(fileHash)
                    
                    #get the similarity score
                    #invert the bin-diff score
                    invertedScore = 0.0
                    for line in log_lines:
                        if "similarity" in line:
                            #print(line)
                            regex_sim = re.compile(r'.([+-]?([0-9]*[.])?[0-9]+).')
                            binDiffScore = regex_sim.findall(line)
                            
                            if len(binDiffScore) == 0:
                                regex_sim = re.compile(r'similarity: ([0-9])')
                                binDiffScore = regex_sim.findall(line)

                            #print(binDiffScore)
                            #print(binDiffScore[0][0])
                            
                            try:
                                invertedScore = 1.0 - float(binDiffScore[0][0])
                            except:
                                print("Couldn't find binDiffScore for file " + file)
                    
                    ##make class for file with filehash
                    #toAppend = fileScores(fileHash)
                    
                    ##set the which score we are getting
                    #if optimization == "O0":
                        #toAppend.setO0(invertedScore)                    
                    #elif optimization == "O1":
                        #toAppend.setO1(invertedScore)
                    #elif optimization == "O2":
                        #toAppend.setO2(invertedScore)
                    #elif optimization == "O3":
                        #toAppend.setO3(invertedScore)
                        
                    tell   = [True if x in basedir else False for x in sub_folders]
                    index  = tell.index(True)
                    subFol = sub_folders[index]            
                    
                    if "openssl" in basedir:                    
                        parent = Folder + "openssl" + subFol
                        sourcename = basedir.replace(parent, "")
                        dictionary = data_openssl[index]                
                        if sourcename not in dictionary:
                            dictionary[sourcename] = []
                            
                        files_hashes = dictionary[sourcename]
                        
                        exists = any([True if x.getName() == fileHash else False for x in files_hashes])
                        if (exists):
                            for f in files_hashes:
                                if f.getName() == fileHash:
                                    #set the which score we are getting
                                    if optimization == "O0":
                                        f.setO0(invertedScore)                    
                                    elif optimization == "O1":
                                        f.setO1(invertedScore)
                                    elif optimization == "O2":
                                        f.setO2(invertedScore)
                                    elif optimization == "O3":
                                        f.setO3(invertedScore)
                                    break
                            
                        else:
                            #make class for file with filehash
                            toAppend = fileScores(fileHash)
                            
                            #set the which score we are getting
                            if optimization == "O0":
                                toAppend.setO0(invertedScore)                    
                            elif optimization == "O1":
                                toAppend.setO1(invertedScore)
                            elif optimization == "O2":
                                toAppend.setO2(invertedScore)
                            elif optimization == "O3":
                                toAppend.setO3(invertedScore)                        
                            files_hashes.append(toAppend)
                            
                    elif "spec" in basedir:
                        parent = Folder + "spec" + subFol
                        sourcename = basedir.replace(parent, "")
                        dictionary = data_spec[index]                
                        if sourcename not in dictionary:
                            dictionary[sourcename] = []
                            
                        files_hashes = dictionary[sourcename]
                        
                        exists = any([True if x.getName() == fileHash else False for x in files_hashes])
                        if (exists):
                            for f in files_hashes:
                                if f.getName() == fileHash:
                                    #set the which score we are getting
                                    if optimization == "O0":
                                        f.setO0(invertedScore)                    
                                    elif optimization == "O1":
                                        f.setO1(invertedScore)
                                    elif optimization == "O2":
                                        f.setO2(invertedScore)
                                    elif optimization == "O3":
                                        f.setO3(invertedScore)
                                    break
                            
                        else:
                            #make class for file with filehash
                            toAppend = fileScores(fileHash)
                            
                            #set the which score we are getting
                            if optimization == "O0":
                                toAppend.setO0(invertedScore)                    
                            elif optimization == "O1":
                                toAppend.setO1(invertedScore)
                            elif optimization == "O2":
                                toAppend.setO2(invertedScore)
                            elif optimization == "O3":
                                toAppend.setO3(invertedScore)                        
                            files_hashes.append(toAppend)
                            
                    elif "coreutils" in basedir:
                        parent = Folder + "coreutils" + subFol
                        sourcename = basedir.replace(parent, "")
                        dictionary = data_coreutils[index]                
                        if sourcename not in dictionary:
                            dictionary[sourcename] = []                   
                        
                        files_hashes = dictionary[sourcename]
                        
                        exists = any([True if x.getName() == fileHash else False for x in files_hashes])
                        if (exists):
                            for f in files_hashes:
                                if f.getName() == fileHash:
                                    #set the which score we are getting
                                    if optimization == "O0":
                                        f.setO0(invertedScore)                    
                                    elif optimization == "O1":
                                        f.setO1(invertedScore)
                                    elif optimization == "O2":
                                        f.setO2(invertedScore)
                                    elif optimization == "O3":
                                        f.setO3(invertedScore)
                                    break
                            
                        else:
                            #make class for file with filehash
                            toAppend = fileScores(fileHash)
                            
                            #set the which score we are getting
                            if optimization == "O0":
                                toAppend.setO0(invertedScore)                    
                            elif optimization == "O1":
                                toAppend.setO1(invertedScore)
                            elif optimization == "O2":
                                toAppend.setO2(invertedScore)
                            elif optimization == "O3":
                                toAppend.setO3(invertedScore)                        
                            files_hashes.append(toAppend)
                    


#print()    
#print("Print all the dictionaries once: ")
#print()
#print(data_coreutils)
#print()
#print(data_openssl)
#print()
#print(data_spec)
#print()

print("Calculating stats for Coreutils...")
for i in range(len(sub_folders)):
    key = sub_folders[i]
    print("Getting results for " + key + "...")
    dictionary_rn = data_coreutils[i]
    #print(dictionary_rn)
    for source in dictionary_rn:
        source_list = dictionary_rn[source]
        O0 = []
        O1 = []
        O2 = [] 
        O3 = []
        for src_file in source_list:
            O0.append(src_file.getO0())
            O1.append(src_file.getO1())
            O2.append(src_file.getO2())
            O3.append(src_file.getO3())
        print("Printing stats for " + source + "...")
        print()
        print("MaxO0")
        print(str(max(O0)))
        print("MaxO1")
        print(str(max(O1)))
        print("MaxO2")
        print(str(max(O2)))
        print("MaxO3")
        print(str(max(O3)))
        print()
        print("MinO0")
        print(str(min(O0)))
        print("MinO1")
        print(str(min(O1)))
        print("MinO2")
        print(str(min(O2)))
        print("MinO3")
        print(str(min(O3)))
        print()
        print("MeanO0")
        print(str(mean(O0)))
        print("MeanO1")
        print(str(mean(O1)))
        print("MeanO2")
        print(str(mean(O2)))
        print("MeanO3")
        print(str(mean(O3)))
        print()
        print("MedianO0")
        print(str(median(O0)))
        print("MeadianO1")
        print(str(median(O1)))
        print("MedianO2")
        print(str(median(O2)))
        print("MedianO3")
        print(str(median(O3)))
        print()
        print("Done printing stats for Coreutils ....")
        
        
print("Calculating stats for Spec...")
for i in range(len(sub_folders)):
    key = sub_folders[i]
    print("Getting results for " + key + "...")
    dictionary_rn = data_spec[i]
    #print(dictionary_rn)
    for source in dictionary_rn:
        source_list = dictionary_rn[source]
        O0 = []
        O1 = []
        O2 = [] 
        O3 = []
        for src_file in source_list:
            O0.append(src_file.getO0())
            O1.append(src_file.getO1())
            O2.append(src_file.getO2())
            O3.append(src_file.getO3())
        print("Printing stats for " + source + "...")
        print()
        print("MaxO0")
        print(str(max(O0)))
        print("MaxO1")
        print(str(max(O1)))
        print("MaxO2")
        print(str(max(O2)))
        print("MaxO3")
        print(str(max(O3)))
        print()
        print("MinO0")
        print(str(min(O0)))
        print("MinO1")
        print(str(min(O1)))
        print("MinO2")
        print(str(min(O2)))
        print("MinO3")
        print(str(min(O3)))
        print()
        print("MeanO0")
        print(str(mean(O0)))
        print("MeanO1")
        print(str(mean(O1)))
        print("MeanO2")
        print(str(mean(O2)))
        print("MeanO3")
        print(str(mean(O3)))
        print()
        print("MedianO0")
        print(str(median(O0)))
        print("MeadianO1")
        print(str(median(O1)))
        print("MedianO2")
        print(str(median(O2)))
        print("MedianO3")
        print(str(median(O3)))
        print()
        print("Done printing stats for Spec ....")
        
print("Calculating stats for Openssl...")
for i in range(len(sub_folders)):
    key = sub_folders[i]
    print("Getting results for " + key + "...")
    dictionary_rn = data_openssl[i]
    #print(dictionary_rn)
    for source in dictionary_rn:
        source_list = dictionary_rn[source]
        O0 = []
        O1 = []
        O2 = [] 
        O3 = []
        for src_file in source_list:
            O0.append(src_file.getO0())
            O1.append(src_file.getO1())
            O2.append(src_file.getO2())
            O3.append(src_file.getO3())
        print("Printing stats for " + source + "...")
        print()
        print("MaxO0")
        print(str(max(O0)))
        print("MaxO1")
        print(str(max(O1)))
        print("MaxO2")
        print(str(max(O2)))
        print("MaxO3")
        print(str(max(O3)))
        print()
        print("MinO0")
        print(str(min(O0)))
        print("MinO1")
        print(str(min(O1)))
        print("MinO2")
        print(str(min(O2)))
        print("MinO3")
        print(str(min(O3)))
        print()
        print("MeanO0")
        print(str(mean(O0)))
        print("MeanO1")
        print(str(mean(O1)))
        print("MeanO2")
        print(str(mean(O2)))
        print("MeanO3")
        print(str(mean(O3)))
        print()
        print("MedianO0")
        print(str(median(O0)))
        print("MeadianO1")
        print(str(median(O1)))
        print("MedianO2")
        print(str(median(O2)))
        print("MedianO3")
        print(str(median(O3)))
        print()
        print("Done printing stats for Openssl ....")
        
#for i in range(len(sub_folders)):
    #key = sub_folders[i]
    #print("Printing max different versions for " + key)
    #print("Openssl")
    #dictionary_ssl = data_openssl[i]
    #for source in dictionary_ssl:
        #print("getting for source " + source)
        #files = dictionary_ssl[source]
        #nameO0   = files[0].getName()
        #nameO3   = files[0].getName()
        #O0_min = files[0].getO0()
        #O3_min = files[0].getO3()
        #for j in range(1, len(files)):
            #if files[j].getO0() > O0_min:
                #nameO0 = files[j].getName()
                #O0_min = files[j].getO0()
                
            #if files[j].getO3() > O3_min:
                #nameO3 = files[j].getName()
                #O3_min = files[j].getO3()
                
                
        #print("O0 max different file is " + nameO0)
        #print("O3 max different file is " + nameO3)
    
        #print("O0 max different score is " + str(O0_min))
        #print("O3 max different score is " + str(O3_min))
    
    #print()
    #print("Coreutils")
    #dictionary_core = data_coreutils[i]
    #for source in dictionary_core:
        #print("getting for source " + source)
        #files = dictionary_core[source]
        #nameO0   = files[0].getName()
        #nameO3   = files[0].getName()
        #O0_min = files[0].getO0()
        #O3_min = files[0].getO3()
        #for j in range(1, len(files)):
            #if files[j].getO0() > O0_min:
                #nameO0 = files[j].getName()
                #O0_min = files[j].getO0()
                
            #if files[j].getO3() > O3_min:
                #nameO3 = files[j].getName()
                #O3_min = files[j].getO3()
                
                
        #print("O0 max different file is " + nameO0)
        #print("O3 max different file is " + nameO3)
    
        #print("O0 max different score is " + str(O0_min))
        #print("O3 max different score is " + str(O3_min))
    
    
    #print()
    #print("Spec..")
    #dictionary_spec = data_spec[i]
    #for source in dictionary_spec:
        #print("getting for source " + source)
        #files = dictionary_spec[source]
        #nameO0   = files[0].getName()
        #nameO3   = files[0].getName()
        #O0_min = files[0].getO0()
        #O3_min = files[0].getO3()
        #for j in range(1, len(files)):
            #if files[j].getO0() > O0_min:
                #nameO0 = files[j].getName()
                #O0_min = files[j].getO0()
                
            #if files[j].getO3() > O3_min:
                #nameO3 = files[j].getName()
                #O3_min = files[j].getO3()
                
                
        #print("O0 max different file is " + nameO0)
        #print("O3 max different file is " + nameO3)
    
        #print("O0 max different score is " + str(O0_min))
        #print("O3 max different score is " + str(O3_min))
    
        















































    
