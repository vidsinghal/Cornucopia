import os
import subprocess


files_folder = "/home/vidush/Applications/afl_sources/"

optimizations = ["O0", "O3"]

for directoryPath, directoryNames, filenames in os.walk(files_folder):
    for filename in filenames:
        if filename.endswith(".bc"):
            filePath = os.path.join(directoryPath, filename)

            make_directory = filePath.replace(".bc", "")
            if (not os.path.exists(make_directory)):
                os.mkdir(make_directory)

            for options in optimizations:
                clang_command = "/home/vidush/Applications/llvm-project-llvmorg-5.0.0-rc5/build/bin/clang -"
                clang_command += options
                clang_command += " -Wl,--unresolved-symbols=ignore-in-object-files "
                clang_command += filePath
                clang_command += " -o "
                clang_command += make_directory
                clang_command += "/"
                clang_command += options

                subprocess.call([clang_command], shell=True)
                print(clang_command)
