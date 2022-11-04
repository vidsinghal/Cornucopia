rootFolder=$(shell pwd)
CC_main=afl-gcc-fast
CXX_postprocessor=g++

all : compile_all get_options

compile_all :
	$(CC_main) fitness_wrapper/main.c -o fitness_wrapper/main -lcurl
	$(CXX_postprocessor) -shared -Wall -fPIC -O3 fitness_wrapper/aflpostprocessor.cc -o fitness_wrapper/aflpostprocessor.so
	$(CXX_postprocessor) -shared -Wall -fPIC -O3 fitness_wrapper/generic_postprocessor.cc -o fitness_wrapper/generic_postprocessor.so
	$(CXX_postprocessor) -shared -Wall -fPIC -O3 fitness_wrapper/multiarch_llvm_postprocessor.cc -o fitness_wrapper/multiarch_llvm_postprocessor.so
	$(CXX_postprocessor) -shared -Wall -fPIC -O3 fitness_wrapper/aflpostprocessor_bin.cc -o fitness_wrapper/aflpostprocessor_bin.so
	$(CXX_postprocessor) -shared -Wall -fPIC -O3 fitness_wrapper/parallel_postprocessor.cc -o fitness_wrapper/parallel_postprocessor.so


get_options : 
	$(rootFolder)/HashEnabledLLVM/build/bin/opt --help-list-hidden > options_list.txt

clean :
	rm fitness_wrapper/main
	rm fitness_wrapper/*.so
	rm options_list.txt
