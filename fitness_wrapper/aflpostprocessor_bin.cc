#include <string>
#include <vector>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

struct Config {
  std::string cc_time;
  std::vector<std::string> optimizationOptions;
  std::string directory;
  std::string output_directory;
  std::string llvm_directory;
  std::string assembly_folder;
  std::string program;
  std::string pname;
  std::string arch;
  unsigned char *outBuffer;
  size_t file_size;
};

std::string getEnvVar( std::string const & key )
{
    char * val = getenv( key.c_str() );
    return val == NULL ? std::string("") : std::string(val);
}

bool is_empty(std::ifstream& pFile)
{
    return pFile.peek() == std::ifstream::traits_type::eof();
}

extern "C" Config *afl_custom_init(void *afl, unsigned int seed) {
    srand(seed);

    Config* config = new Config;

    // char *err;
    // config->cc_time = std::strtold(getEnvVar("RLLVM_CCTIME").c_str(), &err);
    config->cc_time = getEnvVar("RLLVM_CCTIME");
    // if (*err != '\0' || errno != 0) { /* error */ std::abort(); }

    std::fstream file;

    config->directory = getEnvVar("RLLVM_INDIR");
    config->output_directory = getEnvVar("RLLVM_OUTDIR");
    config->llvm_directory = getEnvVar("RLLVM_LLVMBIN");
    config->assembly_folder = getEnvVar("RLLVM_ASSEMBLY");
    config->program = config->directory;
    config->pname = getEnvVar("RLLVM_PNAME");
    config->program += config->pname;
    config->arch = getEnvVar("RLLVM_ARCH");
    config->file_size = UINT_MAX;
    config->outBuffer = new unsigned char[config->file_size * sizeof (unsigned char)];

    struct stat buffer;
    
    std::string command(config->output_directory + "/opt_ERROR/");
    if (stat(command.c_str(), &buffer) != 0){

        std::string makeDir("mkdir " + command);
        std::system(makeDir.c_str());
    }

    std::string command1(config->output_directory + "/opt_SUCCESS/");
    if (stat(command1.c_str(), &buffer) != 0){

        std::string makeDir("mkdir " + command1);
        std::system(makeDir.c_str());
    }

    std::string command2(config->output_directory + "/ClangError/");
    if (stat(command2.c_str(), &buffer) != 0){

        std::string makeDir("mkdir " + command2);
        std::system(makeDir.c_str());
    }

    std::string command3(config->output_directory + "/ClangFileSizeError/");
    if (stat(command3.c_str(), &buffer) != 0){

        std::string makeDir("mkdir " + command3);
        std::system(makeDir.c_str());
    }

    std::string command4(config->output_directory + "/opt_FILE_SIZE/");
    if (stat(command4.c_str(), &buffer) != 0){

        std::string makeDir("mkdir " + command4);
        std::system(makeDir.c_str());
    }

    std::string option_list_path = getEnvVar("RLLVM_OPTIONS_LIST");
    //file to pull the options from the option_list file
    file.open(option_list_path, std::ios::in);

    //populate the options un a vector
    if(file.is_open()){
        std::string line;
        while(std::getline(file, line)){
            config->optimizationOptions.push_back(line);
        }

    }
    else{
        std::cout << "Error opening option_list.txt file" << std::endl;
        exit(1);
    }

    return config;
}

extern "C" int afl_custom_init_trim(void *data, unsigned char *buf, size_t buf_size) {
    return 0;
}

extern "C" int afl_custom_post_trim(void *data, unsigned char success){
    return 1;
}


extern "C" size_t afl_custom_post_process(Config *config, unsigned char *buf, size_t buf_size, unsigned char **out_buf){
    

    //print statements, uncomment for debugging
    //std::cout << std::endl;
    //std::cout << "The buffer size is: " << buf_size << std::endl;
    //std::cout << std::endl;
    //std::cout << "The option vector size is: " << optimizationOptions.size() << std::endl;
    //std::cout << std::endl;
    
    unsigned int i;
    unsigned int intVal;
    std::string command("timeout " + config->cc_time + " ");
    command += (config->llvm_directory + "/opt --march ");
    command += config->arch + " ";

    for(i=0; i<buf_size; i++){
        intVal = (uint) buf[i];
        
        if(i < config->optimizationOptions.size()){
        
            std::string Option(config->optimizationOptions[i]);
            //int_comare variable is used to check if the option string will have any int variable in the string            
            std::string int_compare("int>");
            //N_compare variable to check is the option string requires N(a number) to compile            
            std::string N_compare("N>");
            
            //for options with an int or uint option
            //(intVal % 2 == 1) gives AFL a switch to turn options off and on, otherswise these options will always be included 
            //in the option string
            if ( (Option.find(int_compare) != std::string::npos or Option.find(N_compare) != std::string::npos) && (intVal % 2 == 1)  ){
                
                //seperate the left part of the string using "=" as the delimiter
                std::string delimiter = "=";
                //left_part contains the left part of the option string
                std::string left_part = Option.substr(0, Option.find(delimiter));
                
                //this means that the left part of the option is not in the current compilatio command
                //This check is important to make sure that the post-processor doesn't appent duplicate commands
                //to the option string, otherwise it will lead to collision within the compiler
                if (command.find(left_part) == std::string::npos){
                    left_part += "=";
                    left_part += std::to_string( ((intVal - 1) / 2) );
                    left_part += " ";
                    command += left_part;
                    
                }                
                
            }
            //for options with "=" in it but no intval or uint vals            
            else if (Option.find("=") != std::string::npos && ( intVal % 2 == 1 ) ){

                //again splitting with "=" as the delimiter
                std::string delimiter = "=";
                std::string left_part = Option.substr(0, Option.find(delimiter));
                
                //this means that the option is not already in the command string
                if (command.find(left_part) == std::string::npos){
                    command += Option;
                    command += " ";
                }
            }
            //for all other options
            else{

                //this means that the option is not already in the command string
                if (command.find(Option) == std::string::npos && ( intVal % 2 == 1 ) ){
                    command += Option;
                    command += " ";
                }
            }
        }
    }
    
    //add the program to be compilation string
    command += config->program;
    command += ".bc ";
    command += "-o ";
    command += config->assembly_folder;
    command += config->pname;
    command += ".bc";
    
    //std::cout << "the command given to opt is " << command << "\n";
    
    //print statements for degugging
    // std::cout << std::endl;
    // std::cout << std::endl;
    // std::cout << std::endl;
    // std::cout << command << std::endl;
    // std::cout << std::endl;
    // std::cout << std::endl;
    // std::cout << std::endl;
    
    //get the commmand that needs to be executed on the shell as a char*
    const char *exec_command = command.c_str();
    // std::cout << command.c_str() << std::endl;
    int compile_status_opt;    
    //execute the compilation command on the system
    std::cout << "Compilation started with timeout " << config->cc_time << std::endl;

    try{
	    compile_status_opt = std::system(exec_command);
    } catch (int i){

	    std::cout << "catch block caught an err, with value:" << i << "\n";
	    std::cout << "Command was " << "\n";
	    std::cout << command << "\n";
    }

    //error
    if (compile_status_opt < 0){
        std::cout << "opt crashed, hence compiling the original file with -O0 " << compile_status_opt << std::endl;
        std::hash<std::string> hash_string;
        ulong command_hash = hash_string(command);
        std::string file_name = std::to_string(command_hash);

        //create the filename
        std::string file_path = config->output_directory;
        file_path += "/opt_ERROR/";
        file_path += file_name;
        file_path += ".txt";
        std::ofstream Crash_Data(file_path);

        //write the command that caused the crash to the file
        Crash_Data << command;
        Crash_Data.close();

        //since we crashed compile just with the default command, that is no optimizations
        std::string execption_command(config->llvm_directory + "/opt --O0 --march ");
        execption_command += config->arch + " ";
        execption_command += config->program;
        execption_command += ".bc ";
        execption_command += "-o ";
        execption_command += config->assembly_folder;
        execption_command += config->pname;
        execption_command += ".bc";
        compile_status_opt = std::system(execption_command.c_str());

    }
    else{
        //returned normally
        if(WIFEXITED(compile_status_opt)){

            if(WEXITSTATUS(compile_status_opt) == 0){
                std::cout << "opt compiled properly, return code was:\n";
                std::cout << WEXITSTATUS(compile_status_opt) << std::endl;
            
                std::hash<std::string> hash_string;
                ulong command_hash = hash_string(command);
                std::string file_name = std::to_string(command_hash);

                //create the filename
                std::string file_path = config->output_directory;
                file_path += "/opt_SUCCESS/";
                file_path += file_name;
                file_path += ".txt";
                std::ofstream Success_Data(file_path);

                //write the command that caused the crash to the file
                Success_Data << command;
                Success_Data.close();
            }
            else if(WEXITSTATUS(compile_status_opt) == 254){

                //std::cout << "opt crashed potential file size error " << WEXITSTATUS(compile_status_opt) << std::endl;
                std::hash<std::string> hash_string;
                ulong command_hash = hash_string(command);
                std::string file_name = std::to_string(command_hash);

                //create the filename
                std::string file_path = config->output_directory;
                file_path += "/opt_FILE_SIZE/";
                file_path += file_name;
                file_path += ".txt";
                std::ofstream Crash_Data(file_path);

                //write the command that caused the crash to the file
                Crash_Data << command;
                Crash_Data.close();

                //since we crashed compile just with the default command, that is no optimizations
                std::string execption_command(config->llvm_directory + "/opt --O0 --march ");
                execption_command += config->arch + " ";
                execption_command += config->program;
                execption_command += ".bc ";
                execption_command += "-o ";
                execption_command += config->assembly_folder;
                execption_command += config->pname;
                execption_command += ".bc";

                // std::cout << execption_command.c_str() << std::endl;
                compile_status_opt = std::system(execption_command.c_str());

            }
            else{
                
                //std::cout << "opt crashed, hence compiling the original file with -O0 " << WEXITSTATUS(compile_status_opt) << std::endl;
                std::hash<std::string> hash_string;
                ulong command_hash = hash_string(command);
                std::string file_name = std::to_string(command_hash);

                //create the filename
                std::string file_path = config->output_directory;
                file_path += "/opt_ERROR/";
                file_path += file_name;
                file_path += ".txt";
                std::ofstream Crash_Data(file_path);

                //write the command that caused the crash to the file
                Crash_Data << command;
                Crash_Data.close();

                //since we crashed compile just with the default command, that is no optimizations
                std::string execption_command(config->llvm_directory + "/opt --O0 --march ");
                execption_command += config->arch + " ";
                execption_command += config->program;
                execption_command += ".bc ";
                execption_command += "-o ";
                execption_command += config->assembly_folder;
                execption_command += config->pname;
                execption_command += ".bc";

                // std::cout << execption_command.c_str() << std::endl;
                compile_status_opt = std::system(execption_command.c_str());
            }

        }
        //exited abmornally
        else{

        //std::cout << "opt crashed, hence compiling the original file with -O0 " << compile_status_opt << std::endl;
        std::hash<std::string> hash_string;
        ulong command_hash = hash_string(command);
        std::string file_name = std::to_string(command_hash);

        //create the filename
        std::string file_path = config->output_directory;
        file_path += "/opt_ERROR/";
        file_path += file_name;
        file_path += ".txt";
        std::ofstream Crash_Data(file_path);

        //write the command that caused the crash to the file
        Crash_Data << command;
        Crash_Data.close();

        //since we crashed compile just with the default command, that is no optimizations
        std::string execption_command(config->llvm_directory + "/opt --O0 --march ");
        execption_command += config->arch + " ";
        execption_command += config->program;
        execption_command += ".bc ";
        execption_command += "-o ";
        execption_command += config->assembly_folder;
        execption_command += config->pname;
        execption_command += ".bc";

        // std::cout << execption_command.c_str() << std::endl;
        compile_status_opt = std::system(execption_command.c_str());

        }
    }
    
    //compiled file
    std::string compiledFile(config->assembly_folder + config->pname);
    compiledFile += ".bc";
    std::string compiledBin(config->assembly_folder + "/binaries/" + config->pname);

    //std::string clang_command("ulimit -f 10000000; " + config->llvm_directory + "clang -Wl,--unresolved-symbols=ignore-in-object-files " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);  

    // command copied from here: https://github.com/purs3lab/BinBench#readme
    std::string clang_command;
    if ((config->arch).compare("mips") == 0){
        //./binbench-llvm/build/bin/clang -fstack-size-section -target mips-pc-linux -Wl,--hash-style=sysv -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench tests/simple.c -v
        clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -fstack-size-section -target mips-pc-linux -Wl,--hash-style=sysv -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench -v " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
    }
    else if ((config->arch).compare("x86-64") == 0){
        //./binbench-llvm/build/bin/clang -fstack-size-section -gdwarf-3 -B./executable_binutils -mllvm -debug-only=binbench tests/test.c
        clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -Wl,--unresolved-symbols=ignore-in-object-files -fstack-size-section -gdwarf-3 -B./executable_binutils -mllvm -debug-only=binbench " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
    }
    else if ((config->arch).compare("x86") == 0){
        //./binbench-llvm/build/bin/clang -fstack-size-section -m32 -B./executable_binutils -mllvm -debug-only=binbench tests/test.c
        clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -m32 -Wl,--unresolved-symbols=ignore-in-object-files -fstack-size-section -m32 -B./executable_binutils -mllvm -debug-only=binbench " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
    }
    else if ((config->arch).compare("arm") == 0){
        //./binbench-llvm/build/bin/clang -fstack-size-section --target=armv7-pc-linux -mfloat-abi=soft -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench tests/simple.c
        clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -fstack-size-section --target=armv7-pc-linux -mfloat-abi=soft -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
    }
    else if ((config->arch).compare("mips64") == 0){
        //./binbench-llvm/build/bin/clang -fstack-size-section -target mips64-pc-linux -Wl,--hash-style=sysv -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench tests/simple.c
        clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -fstack-size-section -target mips64-pc-linux -Wl,--hash-style=sysv -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
    }
    else if ((config->arch).compare("aarch64") == 0){
        //./binbench-llvm/build/bin/clang -o./test_outputs/sol_aarch64-pc-linux_O0 -O0 --target=aarch64-pc-linux -gdwarf-3 -Wl,--unresolved-symbols=ignore-in-object-files -fstack-size-section -B./executable_binutils -mllvm -debug-only=binbench test_bitcodes/sol.bc
        clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -o./test_outputs/sol_aarch64-pc-linux_O0 -O0 --target=aarch64-pc-linux -gdwarf-3 -Wl,--unresolved-symbols=ignore-in-object-files -fstack-size-section -B./executable_binutils -mllvm -debug-only=binbench " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
    }
    
    
    const char *exec_clang = clang_command.c_str();
    
    //std::cout << "clang Command was: " << "\n";
    //std::cout << exec_clang << "\n";
    
    int compile_status_clang = 0;
    try{
        compile_status_clang = std::system(exec_clang);
        
    } catch (int i){

	    std::cout << "the catch block caught integer value of " << i << " for clang compilation" << "\n";
	    std::cout << "corresponding opt command was: " << "\n";
	    std::cout << command << "\n";
    
    }   
    
    //error
    if (compile_status_clang < 0){
        
        //std::cout << "Clang exited with compile status" << compile_status_clang << std::endl;
        std::hash<std::string> hash_string;
        ulong command_hash = hash_string(command);
        std::string file_name = std::to_string(command_hash);

        //create the filename        
        std::string file_path = config->output_directory;
        file_path += "/ClangError/";
        file_path += file_name;
        file_path += ".txt";
        std::ofstream Crash_Data(file_path);

        //write the command that caused the crash to the file
        Crash_Data << command.c_str();
        Crash_Data.close();

    }
    else{

        if(WIFEXITED(compile_status_clang)){

            if(WEXITSTATUS(compile_status_clang) == 0){
                std::cout << "Clang compiled successfully!, error code was:\n";
                std::cout << WEXITSTATUS(compile_status_clang) << std::endl;
            }
            else if (WEXITSTATUS(compile_status_clang) == 254){
                std::cout << "Clang exited with potential file size error" << WEXITSTATUS(compile_status_clang) << std::endl;
                std::hash<std::string> hash_string;
                ulong command_hash = hash_string(command);
                std::string file_name = std::to_string(command_hash);

                //create the filename        
                std::string file_path = config->output_directory;
                file_path += "/ClangFileSizeError/";
                file_path += file_name;
                file_path += ".txt";
                std::ofstream Crash_Data(file_path);

                //write the command that caused the crash to the file
                Crash_Data << command.c_str();
                Crash_Data.close();
            }
            else{
                std::cout << "Clang exited with compile status " << WEXITSTATUS(compile_status_clang) << std::endl;
                std::hash<std::string> hash_string;
                ulong command_hash = hash_string(command);
                std::string file_name = std::to_string(command_hash);

                //create the filename        
                std::string file_path = config->output_directory;
                file_path += "/ClangError/";
                file_path += file_name;
                file_path += ".txt";
                std::ofstream Crash_Data(file_path);

                //write the command that caused the crash to the file
                Crash_Data << command.c_str();
                Crash_Data.close();

            }
        }
        else{
            
            std::cout << "std::system didn't exit properly, returned code while compiling clang " << compile_status_clang << std::endl;
            std::hash<std::string> hash_string;
            ulong command_hash = hash_string(command);
            std::string file_name = std::to_string(command_hash);

            //create the filename        
            std::string file_path = config->output_directory;
            file_path += "/ClangError/";
            file_path += file_name;
            file_path += ".txt";
            std::ofstream Crash_Data(file_path);

            //write the command that caused the crash to the file
            Crash_Data << command.c_str();
            Crash_Data.close();
        }
    }
    
    size_t file_size =0;
    //std::string compiledBin;
    if (WEXITSTATUS(compile_status_clang) != 0){

        std::string execption_command(config->llvm_directory + "/opt --O0 --march ");
        execption_command += config->arch + " ";
        execption_command += config->program;
        execption_command += ".bc ";
        execption_command += "-o ";
        execption_command += config->assembly_folder;
        execption_command += config->pname ;
        execption_command += ".bc";
        compile_status_opt = std::system(execption_command.c_str());

        std::string compiledFile(config->assembly_folder + config->pname);
        compiledFile += ".bc";
        //compiledBin = config->assembly_folder + "/binaries/" + config->pname;
        std::string clang_command;
        if ((config->arch).compare("mips") == 0){
            //./binbench-llvm/build/bin/clang -fstack-size-section -target mips-pc-linux -Wl,--hash-style=sysv -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench tests/simple.c -v
            clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -fstack-size-section -target mips-pc-linux -Wl,--hash-style=sysv -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench -v " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
        }
        else if ((config->arch).compare("x86-64") == 0){
            //./binbench-llvm/build/bin/clang -fstack-size-section -gdwarf-3 -B./executable_binutils -mllvm -debug-only=binbench tests/test.c
            clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -Wl,--unresolved-symbols=ignore-in-object-files -fstack-size-section -gdwarf-3 -B./executable_binutils -mllvm -debug-only=binbench " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
        }
        else if ((config->arch).compare("x86") == 0){
            //./binbench-llvm/build/bin/clang -fstack-size-section -m32 -B./executable_binutils -mllvm -debug-only=binbench tests/test.c
            clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -m32 -Wl,--unresolved-symbols=ignore-in-object-files -fstack-size-section -m32 -B./executable_binutils -mllvm -debug-only=binbench " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
        }
        else if ((config->arch).compare("arm") == 0){
            //./binbench-llvm/build/bin/clang -fstack-size-section --target=armv7-pc-linux -mfloat-abi=soft -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench tests/simple.c
            clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -fstack-size-section --target=armv7-pc-linux -mfloat-abi=soft -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
        }
        else if ((config->arch).compare("mips64") == 0){
            //./binbench-llvm/build/bin/clang -fstack-size-section -target mips64-pc-linux -Wl,--hash-style=sysv -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench tests/simple.c
            clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -fstack-size-section -target mips64-pc-linux -Wl,--hash-style=sysv -Wl,--unresolved-symbols=ignore-in-object-files  -B./executable_binutils -mllvm -debug-only=binbench " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
        }
        else if ((config->arch).compare("aarch64") == 0){
            //./binbench-llvm/build/bin/clang -o./test_outputs/sol_aarch64-pc-linux_O0 -O0 --target=aarch64-pc-linux -gdwarf-3 -Wl,--unresolved-symbols=ignore-in-object-files -fstack-size-section -B./executable_binutils -mllvm -debug-only=binbench test_bitcodes/sol.bc
            clang_command = std::string("ulimit -f 10000000; " + config->llvm_directory + "clang -o./test_outputs/sol_aarch64-pc-linux_O0 -O0 --target=aarch64-pc-linux -gdwarf-3 -Wl,--unresolved-symbols=ignore-in-object-files -fstack-size-section -B./executable_binutils -mllvm -debug-only=binbench " + compiledFile + " -o " + config->assembly_folder + "/binaries/" + config->pname);
        }
        const char *exec_clang = clang_command.c_str();
        
        //std::cout << "clang Command was: " << "\n";
        //std::cout << exec_clang << "\n";
        
        int compile_status_clang = std::system(exec_clang);
    }

    std::ifstream compiledFileHandle(compiledBin, std::ios::binary);    
    compiledFileHandle.seekg(0, std::ios::end);
    file_size = compiledFileHandle.tellg();
    
    //write the contents of the compile file to the output buffer
    //allocate the output buffer first
    //unsigned char *out = new unsigned char[file_size * sizeof (unsigned char)];
    //
    
    if(file_size > config->file_size){
	    config->outBuffer = (unsigned char*) realloc(config->outBuffer, file_size * sizeof(unsigned char));
	    config->file_size = file_size;
    }

    compiledFileHandle.clear();
    compiledFileHandle.seekg(0, std::ios::beg);
    
    //std::cout << "The file size in bytes is: " << file_size << std::endl;
    //std::cout << std::endl;
    
    //write to the output buffer
    int j=0;
    char byte;
    while (compiledFileHandle.get(byte)){
        config->outBuffer[j] = byte;
        j++;        
    }   
    
    //std::cout << "The output buffer size is: " << j << std::endl;
    //std::cout << std::endl;
    //assign out to out_buf pointer
    *out_buf = config->outBuffer;

    return file_size;
    
}

extern "C" void afl_custom_deinit(void *data) {
    return;
}
