#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Bitcode/BitcodeWriterPass.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/Regex.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h" 

#include <cassert>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <sys/types.h>
#include <system_error>
#include <utility>
#include <vector>
#include <chrono>
#include <sstream>
#include <iostream>
#include <functional>
#include <string>

using namespace llvm;
using namespace llvm::sys;

namespace{
    
    class emitIRfiles : public ModulePass{
    public:
        static char ID;
        emitIRfiles() : ModulePass(ID) {}
        bool runOnModule(Module &M) override {
            
            auto t1 = std::chrono::system_clock::now();
            
            std::string total_hash; 
            for (Function &F : M)
            {  
                std::string function_body;
                llvm::raw_string_ostream body(function_body);
                F.print(body);
                
                std::hash<std::string> hash_number;
                
                ulong function_hash = hash_number(function_body);
                std::string hash_string = std::to_string(function_hash);                
                total_hash += hash_string;
            }
            
            std::hash<std::string> final_hash;
            
            ulong net = final_hash(total_hash);
            
            outs() << net << "\n";
            
            auto t2 = std::chrono::system_clock::now();
            
            outs() << "Time spent : " << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() << "ms \n";
            
            return false;
            
        }       
    };
}

char emitIRfiles::ID = 0;

static RegisterPass<emitIRfiles> X("Emit-IR-Files", "emit the IR of each function",
    false ,
    false );





