#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from builtins import input
import argparse
import subprocess
import os
import time
import pebble
import json
import tarfile
import re
import shutil
# it is a wrapper around concurrent.futures, allowing us to cancel futures
import logging
import concurrent.futures
import multiprocessing_logging
from threading import Timer
from functools import partial
import csv

fileCount_Iters = {}

TIMEOUT_SINGLE_RUN = "10000"

logging.basicConfig(filename="progress.log", level=logging.INFO)
logger = logging.getLogger()
multiprocessing_logging.install_mp_handler(logger)

class Config(object):
    def __init__(self, config : dict, resume, m):
        self.randollvm_root  = config["RANDOLLVM_ROOT"]
        self.server_url = config["SERVER_URL"]
        self.iterations = config["ITERATIONS"]
        self.downloads = config["DOWNLOADS"]
        self.arch = config["ARCH"]
        self.mode = config["MODE"]
        self.fuzzing_time = config["FUZZING_TIME"]
        self.fitness_function = config["FITNESS_FUNCTION"]
        self.resume = resume
        self.source = config["SOURCE"]
        self.threads = config["THREADS"]
        self.parallel_mode = m

        if self.mode == "GCC":
            self.set_vars_gcc()
        elif self.mode == "LLVM":
            self.set_vars_llvm()

    def get_environ_llvm(self):
        environ_copy = os.environ.copy()
        environ_copy["AFL_CUSTOM_MUTATOR_LIBRARY"] = self.post_processor
        #set this environment variable 
        environ_copy["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        environ_copy["RLLVM_INDIR"] = self.input_bitcodes
        environ_copy["RLLVM_OPTIONS_LIST"] = self.options_list
        environ_copy["RLLVM_LLVMBIN"] = self.llvm_path
        environ_copy["RLLVM_ASSEMBLY"] = self.assembly_folder
        environ_copy["RLLVM_ARCH"] = self.arch
        return environ_copy

    def get_environ_gcc(self):
        environ_copy = os.environ.copy()
        environ_copy["AFL_CUSTOM_MUTATOR_LIBRARY"] = self.post_processor
        environ_copy["COPA_OPTIONS_LIST"] = self.options_list
        environ_copy["COPA_COMPILER"] = "gcc"
        environ_copy["COPA_CXX_COMPILER"] = "g++"
        environ_copy["COPA_ALL_OPTIMIZATION_FLAGS_FILE"] = self.randollvm_root + "/gcc_all_options.txt"
        environ_copy["COPA_CURR_OPTIMIZATION_FLAGS_FILE"] = self.randollvm_root + "/gcc_curr_options.txt"
        return environ_copy

    def set_vars_llvm(self):
        self.fitness_wrapper = self.randollvm_root + "/fitness_wrapper/"
        self.llvm_path = self.randollvm_root + "/BinBench/binbench-llvm/build/bin/"
        self.afl_path = self.randollvm_root + "/AFLplusplus/"
        self.input_bitcodes = self.randollvm_root + "/afl_sources/"
        self.input_optionmaps = self.randollvm_root + "/inputs/"
        self.assembly_folder = self.randollvm_root + "/assembly_folder/"

        if not os.path.isdir(self.assembly_folder):
            os.mkdir(self.assembly_folder)

        self.assembly_folder = self.assembly_folder + self.fitness_function + "/"

        if not os.path.isdir(self.assembly_folder):
            os.mkdir(self.assembly_folder)
            os.mkdir(self.assembly_folder + "/binaries/")

        self.outputs_folder = self.randollvm_root + "/outputs/" + self.fitness_function + "/"
        self.port = self.server_url.split(":")[-1]
         
        if (self.parallel_mode == 1):
            self.post_processor = self.randollvm_root + "/fitness_wrapper" + "/parallel_postprocessor.so"
        else:            
            if (str("function_hash") in self.fitness_function):
                self.post_processor = self.randollvm_root + "/fitness_wrapper" + "/multiarch_llvm_postprocessor.so"
            else:
                self.post_processor = self.randollvm_root + "/fitness_wrapper" + "/aflpostprocessor_bin.so"

        print(self.post_processor)

        self.options_list = self.randollvm_root + "/option_list.txt"
        self.afl_crash_dir = self.randollvm_root + "/llvm_afl_fuzz_crashes/"

        if not os.path.isdir(self.afl_crash_dir):
            os.mkdir(self.afl_crash_dir) 
        
        self.afl_crash_dir += self.fitness_function + "/"
        if not os.path.isdir(self.afl_crash_dir):
            os.mkdir(self.afl_crash_dir)

        self.original_sources = self.downloads + "/original_sources/"
        if not os.path.isdir(self.original_sources):
            os.mkdir(self.original_sources)
        

    def set_vars_gcc(self):
        self.fitness_wrapper = self.randollvm_root + "/fitness_wrapper/"
        self.afl_path = self.randollvm_root + "/AFLplusplus/"
        self.input_srcdirs = self.randollvm_root + "/gcc_sources/"
        self.input_optionmaps = self.randollvm_root + "/inputs/"
        self.input_bindirs = self.randollvm_root + "/gcc_bins/"
        self.outputs_folder = self.randollvm_root + "/gcc_outputs/"
        self.post_processor = self.randollvm_root + "/fitness_wrapper" + "/generic_postprocessor.so"
        self.options_list = self.randollvm_root + "/gcc_afl_options.txt"
        self.afl_crash_dir = self.randollvm_root + "/gcc_afl_fuzz_crashes/"
        self.port = self.server_url.split(":")[-1]

class Input_Binary(object):
    def __init__(self, src_path, bin_path):
        self.bin_name = bin_path.split("/")[-1]
        self.project_name = src_path.split("/")[-1]
        self.src_path = src_path
        self.bin_path = bin_path

def fuzz_bitcode_gcc(input_binary, config):

    prog_name = input_binary.bin_name
    output_path = config.outputs_folder+"/"+prog_name

    if not os.path.isdir(output_path):
        os.mkdir(output_path)
   
    logger.info("STARTED_PROGRAM:" + prog_name)
    environ = config.get_environ_gcc()
    environ["COPA_PNAME"] = "/"+prog_name
    environ["COPA_OUTDIR"] = output_path
    environ["COPA_DESTDIR"] = config.input_bindirs + "/" + input_binary.project_name
    environ["COPA_SRCDIR"] = input_binary.src_path
    environ["COPA_BINPATH"] = input_binary.bin_path
    compilation_time = make_project(input_binary, config, environ)
    environ["COPA_CCTIME"] = str(compilation_time*2) # set timeout at 2 times that of O3 compilation time
    new_path = input_binary.bin_path
    afl_stdout =open(config.afl_crash_dir + prog_name + "_out.txt", "wb")
    afl_stderr =open(config.afl_crash_dir + prog_name + "_err.txt", "wb")
    if config.resume:
        p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              TIMEOUT_SINGLE_RUN, "-i-",
                              "-m", "30000",
                              "-o", output_path,
                              "-E", str(config.iterations),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                             stdout=afl_stdout, stderr=afl_stderr)
    else:
        p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              TIMEOUT_SINGLE_RUN, "-i",
                              config.input_optionmaps, "-o", output_path,
                              "-m", "30000",
                              "-E", str(config.iterations),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                             stdout=afl_stdout, stderr=afl_stderr)


def fuzz_bitcode_llvm(input_file, config, fuzzing_time, instance_time, use_iterations, O3_map):

    outputs_folder = config.outputs_folder
    prog_name = input_file.split("/")[-1].replace(".bc", "")
    output_path = outputs_folder+"/"+prog_name

    if not os.path.isdir(output_path):
        os.mkdir(output_path)

    logger.info("STARTED_PROGRAM:" + prog_name)
    environ = config.get_environ_llvm()
    environ["RLLVM_CCTIME"] = str(O3_map[input_file]*2) #set timeout at 2 times that of O3 compilation time
    environ["RLLVM_PNAME"] = "/"+prog_name
    environ["RLLVM_OUTDIR"] = output_path

    if str("function_hash") in config.fitness_function:
        new_path = config.assembly_folder+"/"+prog_name+".bc"
    else:
        new_path = config.assembly_folder + "/binaries/" + prog_name


    afl_stdout =open(config.afl_crash_dir + prog_name + "_out.txt", "wb")
    afl_stderr =open(config.afl_crash_dir + prog_name + "_err.txt", "wb")

    if use_iterations:

        if config.resume:
            p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i-",
                              "-o", output_path,
                              "-m", "512",
                              "-E", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                             stdout=afl_stdout, stderr=afl_stderr)
        else:

            p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i",
                              config.input_optionmaps, "-o", output_path,
                              "-m", "512",
                              "-E", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                             stdout=afl_stdout, stderr=afl_stderr)

    else:
        
        if config.resume:
            p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i-",
                              "-o", output_path,
                              "-m", "512",
                              "-V", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                             stdout=afl_stdout, stderr=afl_stderr)
        elif config.resume == False:
            p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i",
                              config.input_optionmaps, "-o", output_path,
                              "-m", "512",
                              "-V", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                             stdout=afl_stdout, stderr=afl_stderr)

def compile_bc(input_file, config):
    prog_name = input_file.split("/")[-1].replace(".bc", "")
    start = time.time()
    # TODO: replace llc-12 with environment var or use a config file?
    try:
        subprocess.check_call([config.llvm_path+"/opt", "--O3", "--march=" + config.arch , input_file, "-o", config.assembly_folder+"/"
                    +prog_name+".bc"])
    except:
        print("opt failed for " + input_file )
    end = time.time()
    return end - start

def compile_bc_parallel(isSlave, input_file, config):
    prog_name = input_file.split("/")[-1].replace(".bc", "")
    start = time.time()
    # TODO: replace llc-12 with environment var or use a config file?
    try:
        assembly_folder = config.assembly_folder+"/"+str(isSlave)+"/"
        if not os.path.isdir(assembly_folder):
            os.mkdir(assembly_folder)
        subprocess.check_call([config.llvm_path+"/opt", "--O3", "--march=" + config.arch , input_file, "-o", config.assembly_folder+"/"+str(isSlave)+"/"+prog_name+".bc"])
    except:
        print("opt failed for " + input_file )
    end = time.time()
    return end - start

def compile_O0(input_file, config):
    prog_name = input_file.split("/")[-1].replace(".bc", "")
    if(str("function_hash") in config.fitness_function):
        start = time.time()
        # TODO: replace llc-12 with environment var or use a config file?
        try:
            subprocess.check_call([config.llvm_path+"/opt", "--march=" + config.arch ,"--O0", input_file, "-o", config.original_sources +"/"
                    +prog_name+".bc"])
        except:
            print("opt failed for " + input_file)
        end = time.time()
    #else:
       # start = time.time()
        # TODO: replace llc-12 with environment var or use a config file?

    
    start = time.time()
     
    clang_arch = ""
    if (config.arch == "x86"):
        clang_arch = "-m32"

    try:
        subprocess.check_call([config.llvm_path+"/clang", clang_arch , "-Wl,--unresolved-symbols=ignore-in-object-files", "-O0", input_file, "-o", config.original_sources +"/" 
            +prog_name])
    except:
        print("clang failed for " + input_file)

    end = time.time()

    return end - start

# FIXME: test this
def make_project(input_binary, config, environ):
    start = time.time()
    wd = os.getcwd()
    os.chdir(input_binary.src_path)
    environ["COPA_CURR_OPTIMIZATION_FLAGS_FILE"] = config.randollvm_root + "/empty.txt"
    subprocess.call(["make"], env=environ, shell=True)
    subprocess.call(["make", "install", "DESTDIR=" + config.input_bindirs + input_binary.project_name], env=environ, shell=True)
    shutil.copyfile(input_binary.bin_path, config.downloads + "/original_sources/" + input_binary.bin_name)
    os.chdir(wd)
    end = time.time()
    return end - start

def logging(directory):
   
    for subdir, dirs, files in os.walk(directory):
        fileCount_Iters[subdir] = len(files)

def run_llvm_fuzz(config):
    if not os.path.isdir(config.assembly_folder):
        os.mkdir(config.assembly_folder)
        os.mkdir(config.assembly_folder + "/binaries/")

    if not os.path.isdir(config.outputs_folder):
        os.mkdir(config.outputs_folder)

    progress = read_file("progress.log")
    #print(progress)
    processed = []
    result = re.findall('INFO:root:PROCESSED_PROGRAM:.*', progress)
    for i in result:
        processed.append(i.split(":")[-1]+".bc")

    # Walk through all files in input folder
    input_files = []
    for filename in os.listdir(config.input_bitcodes):
        if filename in processed:
            continue
        f = os.path.join(config.input_bitcodes, filename)
        # checking if it is a file
        if os.path.isfile(f):
            input_files.append(f)
    
    #compile all O0 sources
    with pebble.ProcessPool() as executor:
        compileO0 = partial(compile_O0, config=config)
        try:
            executor.map(compileO0, input_files)
        except KeyboardInterrupt:
            executor.stop()

    
    #get the O3 timings for all the sources
    O3_compile_time_map = {}

    with pebble.ProcessPool() as executor:
        compileO3 = partial(compile_bc, config=config)
        try:
            mapFuture = executor.map(compileO3, input_files)
        except KeyboardInterrupt:
            executor.stop()

    for i, time_O3 in zip(input_files, mapFuture.result()):
        O3_compile_time_map[i] = time_O3

    fuzz_time_t = 3600000 #set to a large number (1hr)
    
    #set to 94 coz one core taken up my runfuzz and one by the server
    number_of_cores = int(config.threads)

    num_batches = (int) (len(input_files) / number_of_cores)

    batches_done = 0
    while(batches_done < num_batches):


        start_index = batches_done * number_of_cores
        print(start_index)
        end_index = (batches_done + 1) * number_of_cores
        print(end_index)

        file_this_batch = input_files[start_index : end_index]
        print(file_this_batch)
        
        with pebble.ProcessPool() as executor:
            fuzz = partial(fuzz_bitcode_llvm, config=config, fuzzing_time=config.fuzzing_time, instance_time=str(fuzz_time_t), use_iterations=False, O3_map=O3_compile_time_map)
            try:
                executor.map(fuzz, file_this_batch)
            except KeyboardInterrupt:
                executor.stop()

        time.sleep(2)
        fuzzing_time = time.time()
        
        total_fuzz_time = int(config.fuzzing_time)

        while(True):

            if( (time.time() - fuzzing_time) > total_fuzz_time):
                subprocess.call("killall -9 afl-fuzz clang-12 clang opt opt-12", shell=True)
                subprocess.call("ipcrm -a", shell=True)
                batches_done = batches_done + 1
                break
            time.sleep(30)


    #last batch
    batch_index = batches_done * number_of_cores
    last_index  = len(input_files) 

    files_left = input_files[batch_index:last_index]
    
    with pebble.ProcessPool() as executor:
        fuzz = partial(fuzz_bitcode_llvm, config=config, fuzzing_time=config.fuzzing_time, instance_time=str(fuzz_time_t), use_iterations=False, O3_map=O3_compile_time_map)
        try:
            executor.map(fuzz, files_left)
        except KeyboardInterrupt:
            executor.stop()

#running afl++ in single source parallel instances
def fuzz_bitcode_llvm_parallel(isSlave, input_file, config, fuzzing_time, instance_time, use_iterations, O3_map):

    outputs_folder = config.outputs_folder
    prog_name = input_file.split("/")[-1].replace(".bc", "")
    
    #master and slave will now have different output paths
    output_path = outputs_folder

    #slave mode    
    if("slave" in isSlave):
        logger.info("STARTED_PROGRAM " + prog_name + " in slave mode " + str("slave ID is ") + str(isSlave))
        output_path = output_path + "/" + str(isSlave)
        if not os.path.isdir(output_path):
            os.mkdir(output_path)
        
        if str("function_hash") in config.fitness_function:
            #assembly file case
            new_path = config.assembly_folder+"/"+ str(isSlave) + "/"
            if not os.path.isdir(new_path):
                os.mkdir(new_path)
            new_path = new_path + prog_name+".bc"
        else:
            #binary file case            
            new_path = config.assembly_folder + "/binaries" + "/" 
            if not os.path.isdir(new_path):
                os.mkdir(new_path)                
            new_path = new_path + "/" + str(isSlave) + "/"
            if not os.path.isdir(new_path):
                os.mkdir(new_path)                
            new_path = new_path + prog_name

    #master mode        
    else:
        logger.info("STARTED_PROGRAM " + prog_name + " in master mode")
        output_path = output_path + "/" + "master"
        if not os.path.isdir(output_path):
            os.mkdir(output_path)
            
        if str("function_hash") in config.fitness_function:
            #assembly file case
            new_path = config.assembly_folder+"/"+ "master" + "/"
            if not os.path.isdir(new_path):
                os.mkdir(new_path)            
            new_path = new_path + prog_name+".bc"
        else:
            #binary file case
            new_path = config.assembly_folder + "/binaries/"            
            if not os.path.isdir(new_path):
                os.mkdir(new_path)
            new_path = config.assembly_folder+"/"+ "master" + "/"
            if not os.path.isdir(new_path):
                os.mkdir(new_path)
            new_path = new_path + prog_name
    
    #set afl crash dir
    slave_crash_dir = config.afl_crash_dir + "/" + str(isSlave) + "/" 
    if not os.path.isdir(slave_crash_dir):
        os.mkdir(slave_crash_dir)
            
    afl_stdout =open(slave_crash_dir + prog_name + "_out.txt", "wb")
    afl_stderr =open(slave_crash_dir + prog_name + "_err.txt", "wb")
    
    #give output path correct program name
    output_path = output_path+"/"+prog_name
    if not os.path.isdir(output_path):
        os.mkdir(output_path)

    environ = config.get_environ_llvm()
    #change the assembly folder since it will differ for master and slave now
    if ("slave" in isSlave):
        environ["RLLVM_ASSEMBLY"] = config.assembly_folder+"/"+ str(isSlave) + "/"
    else:
        environ["RLLVM_ASSEMBLY"] = config.assembly_folder+"/"+"master"+"/"      

    #set timeout at 2 times that of O3 compilation time
    environ["RLLVM_CCTIME"] = str(O3_map[input_file]*2) 
    environ["RLLVM_PNAME"] = "/"+prog_name
    environ["RLLVM_OUTDIR"] = output_path

    if use_iterations:
        if config.resume:
            if("slave" in isSlave):
                p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i-",
                              "-o", output_path,
                              "-S", str(isSlave),
                              "-m", "512",
                              "-E", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                              stdout=afl_stdout, stderr=afl_stderr)
            else:
                p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i-",
                              "-o", output_path,
                              "-M", "master",                              
                              "-m", "512",
                              "-E", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                              stdout=afl_stdout, stderr=afl_stderr)

        else:
            if("slave" in isSlave):
                p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i",
                              config.input_optionmaps, "-o", output_path,
                              "-S", str(isSlave),
                              "-m", "512",                              
                              "-E", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                              stdout=afl_stdout, stderr=afl_stderr)
            else:
                p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i",
                              config.input_optionmaps, "-o", output_path,
                              "-M", "master",
                              "-m", "512",                              
                              "-E", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                              stdout=afl_stdout, stderr=afl_stderr)
    else:
        if config.resume:
            if("slave" in isSlave):
                p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i-",
                              "-o", output_path,
                              "-S", str(isSlave),
                              "-m", "512",                              
                              "-V", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                              stdout=afl_stdout, stderr=afl_stderr)
            else:
                p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i-",
                              "-o", output_path,
                              "-M", "master",
                              "-m", "512",                              
                              "-V", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                              stdout=afl_stdout, stderr=afl_stderr)

        elif config.resume == False:
            if("slave" in isSlave):
                p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t",
                              instance_time, "-i",
                              config.input_optionmaps, "-o", output_path,
                              "-S", str(isSlave),
                              "-m", "512",                              
                              "-V", str(fuzzing_time),
                              config.fitness_wrapper+"/main", new_path, config.server_url],env=environ,
                              stdout=afl_stdout, stderr=afl_stderr)
            else:
                p = subprocess.Popen([config.afl_path + "/afl-fuzz", "-f", new_path, "-t", instance_time, "-i", 
                                      config.input_optionmaps, "-o", output_path, "-M", "master", "-m", "512",
                                      "-V", str(fuzzing_time), config.fitness_wrapper+"/main", new_path, config.server_url], env=environ, stdout=afl_stdout, stderr=afl_stderr)


def run_llvm_fuzz_parallel(config):
    if not os.path.isdir(config.assembly_folder):
        os.mkdir(config.assembly_folder)
        os.mkdir(config.assembly_folder + "/binaries/")

    if not os.path.isdir(config.outputs_folder):
        os.mkdir(config.outputs_folder)

    progress = read_file("progress.log")
    processed = []
    result = re.findall('INFO:root:PROCESSED_PROGRAM:.*', progress)
    for i in result:
        processed.append(i.split(":")[-1]+".bc")

    input_files = []
    if os.path.isfile(config.source):
        input_files.append(str(config.source))


    num_instances = int(config.threads)
    print(num_instances)
    instance_name = []
    instance_name.append( str("master") )
    for i in range(1, num_instances):
        instance_name.append( "slave" + str(i) )
    
    #compile all O0 sources
    with pebble.ProcessPool() as executor:
        compileO0 = partial(compile_O0, config=config)
        try:
            executor.map(compileO0, input_files)
        except KeyboardInterrupt:
            executor.stop()
    
    # #get the O3 timings for all the sources
    O3_compile_time_map = {}

    with pebble.ProcessPool() as executor:
        compileO3 = partial(compile_bc_parallel, input_file=input_files[0], config=config)
        try:
            mapFuture = executor.map(compileO3, instance_name)
        except KeyboardInterrupt:
            executor.stop()

    for i, time_O3 in zip(input_files, mapFuture.result()):
        O3_compile_time_map[i] = time_O3
    
    #set to a large number (1hr)
    fuzz_time_t = 3600000 

    with pebble.ProcessPool() as executor:
        fuzz = partial(fuzz_bitcode_llvm_parallel, input_file=input_files[0], config=config, fuzzing_time=config.fuzzing_time, instance_time=str(fuzz_time_t), use_iterations=False, O3_map=O3_compile_time_map)
        try:
            executor.map(fuzz, instance_name)
        except KeyboardInterrupt:
            executor.stop()



def run_gcc_fuzz(config):
    if not os.path.isdir(config.input_bindirs):
        print("Please make sure configure_copa.py was run and the gcc_bins folder exists")

    if not os.path.isdir(config.outputs_folder):
        os.mkdir(config.outputs_folder)   

    progress = read_file("progress.log")
    processed = []
    result = re.findall('INFO:root:PROCESSED_PROGRAM:.*', progress)
    for i in result:
        processed.append(i.split(":")[-1])

    inputs = []
    for direc in os.listdir(config.input_bindirs):
        input_srcpath = config.input_srcdirs + "/" + direc
        for subdir, dirs, files in os.walk(config.input_bindirs + direc):
            if subdir.endswith("/bin"):
                # FIXME: test this
                for File in files:
                    input_binpath = subdir +"/" +File
                    magic = open(input_binpath, "rb").read(4)
                    if magic == b'\x7fELF':
                        inputs.append(Input_Binary(input_srcpath, input_binpath))

    for i in inputs:
        print(i.src_path + " : " + i.bin_path)
        make_project(i, config, config.get_environ_gcc())
        fuzz_bitcode_gcc(i, config)

def main():
    parser = argparse.ArgumentParser(description="""HighF-level script to run various
    fuzzing instances for each binary on a given set of binaries.""")

    parser.add_argument('config_file', metavar='config_file',
                        help='config file with paths and parameters')
    # TODO: add variable that allows resuming

    parser.add_argument('-r', '--resume', action='store_true')

    #TODO: add a variable that allows fuzzing single binary in parallel mode
    parser.add_argument('-m', metavar='fuzzmode', type=int, help='1 for single source parallel fuzzing, 0 for multi-souce parallel fuzzing')
    args = parser.parse_args()
    config = Config(json.loads(read_file(args.config_file)), args.resume, args.m)

    if config.mode == "GCC":
        run_gcc_fuzz(config)
    elif config.mode == "LLVM":
        if args.m == 0:
            run_llvm_fuzz(config)
        elif args.m == 1:
            #TODO: add the single source function here
            run_llvm_fuzz_parallel(config)
        else:
            print("Please choose the correct mode here, see help for the available modes")
            exit(1)

# Utility Functions
def read_file(path):
    with open(path, "r") as fd:
        data = fd.read()
        return data

def make_tarfile(source_dir, output_filename):
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))

if __name__ == "__main__":
    main()
