import subprocess
import os
import sys
import re
import math
import statistics

#folders_core_utils = [
# "["        , "basenc" , "chown"   , "csplit"   ,  "dir"       ,  "env"    ,  "fmt"    ,  "id"      ,  "ln"      ,  "mkfifo" ,  "nl"     ,  "paste"   ,  "printf"   ,  "rm"      ,  "sha224sum" ,  "shuf"  ,  "stty" ,  "tee"     ,  "true"     ,  "unexpand" ,  "vdir"   ,  "yes" ,
# "b2sum"    , "cat"    ,  "chroot" ,  "cut"     ,  "dircolors" ,  "expand" ,  "fold"   ,  "install" ,  "logname" ,  "mknod"  ,  "nohup"  ,  "pathchk" ,  "ptx"      ,  "rmdir"   ,  "sha256sum" ,  "sleep" ,  "sum"  ,  "test"    ,  "truncate" ,  "uniq"     ,  "wc"     ,
# "base32"   , "chcon"  ,  "cksum"  ,  "date"    ,  "dirname"   ,  "expr"   ,  "groups" ,  "join"    ,  "ls"      ,  "mktemp" ,  "nproc"  ,  "pinky"   ,  "pwd"      ,  "runcon"  ,  "sha384sum" ,  "sort"  ,  "sync" ,  "timeout" ,  "tsort"    ,  "unlink"   ,  "who"    ,
# "base64"   , "chgrp"  ,  "comm"   ,  "dd"      ,  "du"        ,  "factor" ,  "head"   ,  "kill"    ,  "md5sum"  ,  "mv"     ,  "numfmt" ,  "pr"      ,  "readlink" ,  "seq"     ,  "sha512sum" ,  "split" ,  "tac"  ,  "touch"   ,  "tty"      ,  "uptime"   ,  "whoami" ,
# "basename" , "chmod"  ,  "cp"     ,  "df"      ,  "echo"      ,  "false"  ,  "hostid" ,  "link"    ,  "mkdir"   ,  "nice"   ,  "od"     ,  "printenv",  "realpath" ,  "sha1sum" ,  "shred"     ,  "stat"  ,  "tail" ,  "tr"      ,  "uname"    ,  "users" ]

folders_core_utils = ["coreutils"]

files_folder  = "/home/vidush/Applications/cornucopiaRevisionBinaries/"

filename   = "binaries_data.txt"
filehandle = open(filename, 'w') 

for directoryPath, directoryNames, filenames in os.walk(files_folder):
    if ("openssl" in directoryPath or "spec" in directoryPath):

        if len(filenames) != 0:
            filehandle.write(directoryPath)
            filehandle.write("\n")
            filehandle.write(str(len(filenames)))
            filehandle.write("\n")


coreutils_folders = ["bintuner_emulated", "bintuner_orig", "cornucopia_single"]
CoreUtilsInfo = [{}, {}, {}, {}]

folders_core_utils = ["/" + x + "/" for x in folders_core_utils]
print(folders_core_utils)

for directoryPath, directoryNames, filenames in os.walk(files_folder):

    if ("coreutils" in directoryPath):
        
        check_dir = directoryPath+"/"        
        check_valid_source = [True if x in check_dir else False for x in folders_core_utils]
        print(check_dir)
        if (any(check_valid_source)):
            if len(filenames) != 0:
                tellList = [True if x in directoryPath else False for x in coreutils_folders]
                index = tellList.index(True)

                folder_rn = coreutils_folders[index]
                dict_rn   = CoreUtilsInfo[index]
            
                path_bef_source = files_folder + "coreutils/" + folder_rn + "/"
                source_name = directoryPath.replace(path_bef_source, "")
                dict_rn[source_name] = len(filenames)


for item in CoreUtilsInfo:
    print()
    print(item)
    print()

for i in range(len(coreutils_folders)):
    folder_name = coreutils_folders[i]
    dict_folder  = CoreUtilsInfo[i]
    print()
    print(folder_name)
    max_file = max(dict_folder, key=dict_folder.get)
    print("Maximum: ")
    print(max_file)
    print(dict_folder[max_file])
    min_file = min(dict_folder, key=dict_folder.get)
    print("Minimum: ")
    print(min_file)
    print(dict_folder[min_file])
    print("Average: ")
    res = sum(dict_folder.values()) / len(dict_folder)
    print(res)
    print("Median: ")
    listVals = list(dict_folder.values())
    median = statistics.median(listVals)
    print(median)




filehandle.close()

