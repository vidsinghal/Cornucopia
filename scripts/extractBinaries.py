import os
import subprocess
import concurrent.futures
import shutil
import multiprocessing_logging
import pebble
import logging

logging.basicConfig(filename="progress.log", level=logging.INFO)
logger = logging.getLogger()
multiprocessing_logging.install_mp_handler(logger)
TIMEOUT=1800

def compile(tuple_info):

    (directoryPath, directoryNames, filename, extracted_folder) = tuple_info

    if filename.endswith(".s"):
            filePath = os.path.join(directoryPath, filename)
            print("Compiling for file: " + filePath)
            #print(filename)
            #print(directoryPath)
            directoryPathNew = extracted_folder + "/" + directoryPath.replace(files_folder, "") + "/"
            newDirPath = directoryPathNew
            if (not os.path.exists(newDirPath)):
                os.makedirs(newDirPath)

            binaryname = filename.replace(".s", "")
            newBinPath = newDirPath + binaryname

            #print(binaryname)
            print()
            print()

            p = subprocess.Popen(["/home/vidush/Applications/llvm-project-llvmorg-5.0.0-rc5/build/bin/clang", "-Wl,--unresolved-symbols=ignore-in-object-files" , filePath, "-o", newBinPath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
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
                print("[FAIL] Compiled file", filePath)
                return False

            print("[SUCCESS] Compiled file", filePath)
            return True

    elif filename.endswith(".bin") and "spec" not in directoryPath:
            filePath = os.path.join(directoryPath, filename)
            print("Compiling for file: " + filePath)
            #print(filename)
            #print(directoryPath)
            directoryPathNew = extracted_folder + "/" + directoryPath.replace(files_folder, "") + "/"
            newDirPath = directoryPathNew
            if (not os.path.exists(newDirPath)):
                os.makedirs(newDirPath)

            binaryname = filename.replace(".bin", "")
            newBinPath = newDirPath + binaryname

            #print(binaryname)
            print()
            print()

            p = subprocess.Popen(["/home/vidush/Applications/llvm-project-llvmorg-5.0.0-rc5/build/bin/llc", filePath, "-o", newBinPath + ".s"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
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
                print("[FAIL] Compiled file", filePath)
                return False

            print("[SUCCESS] Compiled file", filePath)

            p = subprocess.Popen(["/home/vidush/Applications/llvm-project-llvmorg-5.0.0-rc5/build/bin/clang", "-Wl,--unresolved-symbols=ignore-in-object-files" , newBinPath + ".s", "-o", newBinPath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
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
                print("[FAIL] Compiled file", filePath)
                return False

            print("[SUCCESS] Compiled file", filePath)
            return True


def main():

    global files_folder
    files_folder = "/home/vidush/Applications/cornucopiaRevision/"
    extracted_folder = "/home/vidush/Applications/cornucopiaRevisionBinaries/"

    if (not os.path.exists(extracted_folder)):
        os.mkdir(extracted_folder)

    make_inputs = []
    for directoryPath, directoryNames, filenames in os.walk(files_folder):
        for filename in filenames:
            newTuple = (directoryPath, directoryNames, filename, extracted_folder)
            make_inputs.append(newTuple)

    #sequential
    #for item in make_inputs:
    #    compile(item)
    
    #parallel
    with pebble.ProcessPool() as executor:
       try:
           mapFuture = executor.map(compile, make_inputs)
       except KeyboardInterrupt:
           executor.stop()

if __name__ == "__main__":
    main()
