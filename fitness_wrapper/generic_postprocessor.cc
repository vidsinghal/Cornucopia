#include <string>
#include <vector>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct Config {
    std::string cc_time;
    std::vector<std::string> optimizationOptions;
    std::string source_directory;
    std::string output_directory;
    std::string bin_path;
    std::string curr_options;
    std::string copa_destdir;
    std::string pname;
};

std::string getEnvVar( std::string const & key )
{
    char * val = getenv( key.c_str() );
    return val == NULL ? std::string("") : std::string(val);
}

extern "C" Config *afl_custom_init(void *afl, unsigned int seed) {
    srand(seed);

    Config* config = new Config;

    // char *err;
    // config->cc_time = std::strtold(getEnvVar("RLLVM_CCTIME").c_str(), &err);
    config->cc_time = getEnvVar("COPA_CCTIME");
    config->copa_destdir = getEnvVar("COPA_DESTDIR");
    // if (*err != '\0' || errno != 0) { /* error */ std::abort(); }

    std::fstream file;

    config->source_directory = getEnvVar("COPA_SRCDIR");
    config->output_directory = getEnvVar("COPA_OUTDIR");
    // config->llvm_directory = getEnvVar("RLLVM_LLVMBIN");
    config->bin_path = getEnvVar("COPA_BINPATH");
    config->pname = getEnvVar("COPA_PNAME");
    config->curr_options = getEnvVar("COPA_CURR_OPTIMIZATION_FLAGS_FILE");

    std::string option_list_path = getEnvVar("COPA_OPTIONS_LIST");
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

    std::string cc_options;
    unsigned int i;
    unsigned int intVal;
    
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
                if (cc_options.find(left_part) == std::string::npos){
                    left_part += "=";
                    left_part += std::to_string( ((intVal - 1) / 2) );
                    left_part += "\n";
                    cc_options += left_part;
                    
                }                
                
            }
            //for options with "=" in it but no intval or uint vals            
            else if (Option.find("=") != std::string::npos && ( intVal % 2 == 1 ) ){

                //again splitting with "=" as the delimiter
                std::string delimiter = "=";
                std::string left_part = Option.substr(0, Option.find(delimiter));
                
                //this means that the option is not already in the command string
                if (cc_options.find(left_part) == std::string::npos){
                    cc_options += Option;
                    cc_options += "\n";
                }
            }
            //for all other options
            else{

                //this means that the option is not already in the command string
                if (cc_options.find(Option) == std::string::npos && ( intVal % 2 == 1 ) ){
                    cc_options += Option;
                    cc_options += "\n";
                }
            }
        }
    }
    // std::cout << cc_options << std::endl;

    std::ofstream Curr_Options(config->curr_options);

    //write the command that caused the crash to the file
    Curr_Options << cc_options;
    Curr_Options.close();
    //add the program to be compilation string
    // TODO: go to program directory and hit make
    // FIXME: add the timeout back
    std::string command("(cd " + config->source_directory + " && make && make install DESTDIR=" + config->copa_destdir + ") &");
    const char *exec_command = command.c_str();
    int compile_status;    
    compile_status = std::system(exec_command);

    //print the compile status returned (optional)
    //just a print statement
    // std::cout << "The compilation returned " << std::to_string(compile_status) << std::endl;
    //compiled file
    std::string compiledFile(config->bin_path);

    //if empty file is produced.
    //generate the original program instead.
    //stat will check if the file in empty or not
    //FIXME: this will not work for gcc as the make command can fail and the previous binary is not overwritten
    // we can check make command output to counter this?
    struct stat buffer;
    if ( stat(compiledFile.c_str(), &buffer) != 0 )  
    {
        //empty file is produced so write the options string that caused the crash to a file and store in
        //Crashes directory. The directory will contain all the crahes
        //make a hash out of the option string to get the name of the file
        std::hash<std::string> hash_string;
        ulong command_hash = hash_string(command);
        std::string file_name = std::to_string(command_hash);

        //create the filename        
        std::string file_path = config->output_directory;
        file_path += "Crashes/";
        file_path += file_name;
        file_path += ".txt";
        std::ofstream Crash_Data(file_path);

        //write the command that caused the crash to the file
        Crash_Data << command;
        Crash_Data.close();

        //NOTE: no need to recompile as file will already exist
        //since we crashed compile just with the default command, that is no optimizations
        // std::string execption_command(config->llvm_directory + "/llc ");
        // execption_command += config->program;
        // execption_command += ".bc ";
        // execption_command += "-o ";
        // execption_command += config->assembly_folder;
        // execption_command += config->pname + ".s";

        // std::cout << execption_command.c_str() << std::endl;
        // compile_status = std::system(execption_command.c_str());
        
        //print the compile status returned (optional)
        // std::cout << "The compilation returned " << std::to_string(compile_status) << std::endl;
        
    }

    std::ifstream compiledFileHandle(compiledFile, std::ios::binary);    
    compiledFileHandle.seekg(0, std::ios::end);
    size_t file_size = compiledFileHandle.tellg();
    
    //write the contents of the compile file to the output buffer
    //allocate the output buffer first
    unsigned char *out = new unsigned char[file_size * sizeof (unsigned char)];
    compiledFileHandle.clear();
    compiledFileHandle.seekg(0, std::ios::beg);
    
    //std::cout << "The file size in bytes is: " << file_size << std::endl;
    //std::cout << std::endl;
    
    //write to the output buffer
    int j=0;
    char byte;
    while (compiledFileHandle.get(byte)){
        out[j] = byte;
        j++;        
    }   
    
    //std::cout << "The output buffer size is: " << j << std::endl;
    //std::cout << std::endl;
    //assign out to out_buf pointer
    *out_buf = out;

    return file_size;
}

extern "C" void afl_custom_deinit(void *data) {
    return;
}
