#########################################################
#
# This is a parser written in python that parses the llc
# options and writes them to a file, as input give this 
# program the llc hidden options in the list format.
# This will use that to parse it and output to the file
#
#########################################################
import sys
import copy

architecture_list = [    
    "aarch"       ,
    "amd"         ,
    "arm"         , 
    "avr"         ,
    "bpf"         , 
    "hexagon"     ,
    "lanai"       ,
    "mips"        ,
    "msp430"      ,
    "nvptx"       ,
    "ppc"         ,
    "r600"        ,
    "riscv"       ,
    "sparc"       ,
    "systemz"     ,
    "thumb"       , 
    "wasm"        ,
    "x86"         ,
    "xcore"     
]

if len(sys.argv) < 3:
    print("Please specify file name and architectecture")
    print("USAGE: python3 optionParser.py llcOptionsfile architectureName")
    print("The architecture names should be chosen from the following: ")
    print("-------------------------------------------------------------------------")
    for archs in architecture_list:
        print(archs)
    print("-------------------------------------------------------------------------")
    exit(1)


filename = str(sys.argv[1])

architectureName = str(sys.argv[2])

raw_options = open(filename, 'r')

raw_lines = raw_options.readlines()

raw_lines = [line.strip() for line in raw_lines]

relevant_lines = [line for line in raw_lines if  line.startswith("--")]

relevant_lines = [((line.split(" - ")[0]).strip("-")).strip() for line in relevant_lines]

relevant_lines = ["--" + str(line) for line in relevant_lines]

relevant_lines = [line.split("=") for line in relevant_lines]

relevant_lines_duplicate = copy.deepcopy(relevant_lines)

def add_options_value(string_option):
    
    start_index = 0
    
    for items in raw_lines:
        start_index += 1
        if (items.startswith(string_option) and str("=") in items):
            break
    
    #get the first most useful option for the current option
    current_option = raw_lines[start_index]
    if (not current_option.startswith("--")):
        inter_option = (current_option.split(" - ")[0]).strip()
        final_option = string_option + inter_option
        iterate_options.append( ( final_option ) )
    
    while(True):
        start_index += 1
        current_option = raw_lines[start_index]
        if (current_option.startswith("--")):
            break
        inter_option = (current_option.split(" - ")[0]).strip()
        final_option = string_option + inter_option
        iterate_options.append( ( final_option ) )

def add_options_string(string_option):
    
    start_index = 0
    
    for items in raw_lines:
        start_index += 1
        if (items.startswith(string_option) and str("=") in items):
            break
    
    #get the first most useful option for the current option
    current_option = raw_lines[start_index]
    if (not current_option.startswith("--")):
        inter_option = (current_option.split(" ")[0]).strip()
        if (not inter_option.startswith("=")):
            inter_option = "=" + inter_option
        final_option = string_option + inter_option
        iterate_options.append( ( final_option ) )
    
    while(True):
        start_index += 1
        current_option = raw_lines[start_index]
        if (current_option.startswith("--")):
            break
        inter_option = (current_option.split(" ")[0]).strip()
        if (not inter_option.startswith("=")):
            inter_option = "=" + inter_option
        final_option = string_option + inter_option
        iterate_options.append( ( final_option ) )
    
    
#make a list for all the options to be written to file
iterate_options = []

for options in relevant_lines:
    
    if(len(options) > 1):
        
        if(str("view") in options[0]):
            relevant_lines_duplicate.remove(options)
            continue        
        elif(str("remarks") in options[0]):
            relevant_lines_duplicate.remove(options)
            continue            
        elif(str("int") in options[1]):
            iterate_options.append(options[0] + "=" + options[1])
            relevant_lines_duplicate.remove(options)
        elif(str("file") in options[0] or str("file") in options[1]):
            relevant_lines_duplicate.remove(options)
            continue
        elif(str("value") in options[1]):
            add_options_value(options[0])
            relevant_lines_duplicate.remove(options)
        elif(str("N") in options[1]):
            iterate_options.append(options[0] + "=" + options[1])
            relevant_lines_duplicate.remove(options)
        elif(str("--start") in options[0] or str("--stop") in options[0]):
            relevant_lines_duplicate.remove(options)
        elif (str("string") in options[1]):
            add_options_string(options[0])
            relevant_lines_duplicate.remove(options)    
        elif(str("analysis") in options[0]):
            relevant_lines_duplicate.remove(options)       
            
    else:
        if(str("help") in options[0]):
            relevant_lines_duplicate.remove(options)            
        elif(str("remarks") in options[0]):
            relevant_lines_duplicate.remove(options)
        elif(str("view") in options[0]):
            relevant_lines_duplicate.remove(options)
        elif(str("warn") in options[0]):
            relevant_lines_duplicate.remove(options)
        elif(str("print") in options[0]):
            relevant_lines_duplicate.remove(options)
        elif(str("file") in options[0]):
            relevant_lines_duplicate.remove(options)
        elif(str("--start") in options[0] or str("--stop") in options[0]):
            relevant_lines_duplicate.remove(options)
        elif(str("analysis") in options[0]):
            relevant_lines_duplicate.remove(options)
        else:
            iterate_options.append(options[0])
            relevant_lines_duplicate.remove(options)



#remove the given architecture option 
arch_duplicate = copy.deepcopy(architecture_list)
arch_duplicate.remove(architectureName)

new_list_options = copy.deepcopy(iterate_options)

#Remove all the un-necessary architectures
for option in iterate_options:
    for architectures in arch_duplicate:
        if architectures in option:
            new_list_options.remove(option)
            relevant_lines_duplicate.append(option)
            break

output_file = open("option_list.txt", "w")

for option in new_list_options:
    option.strip()
    output_file.write(option + "\n")
            
print()

print("The number of options that were parsed are: " + str(len(new_list_options)))
print("The options that were parsed and will be added to options file are: ")
print(new_list_options)

print()

print("The options that were not parsed and will not be added to file are: ")
print(relevant_lines_duplicate)

print()
