# A Docker Image for Cornucopia

This is a docker image that will build Cornucopia with all the correct dependencies installed. 

To build the image execute the following command in the main directory

    docker image build -t cornucopia .

The above command will build the cornucopia docker image. We can then access it and play around inside the environment. 
To run the docker image we just built, run the following command

    docker run -p 5001:5001 -t -i cornucopia

Once we have run this command we will enter a bash terminal where all the files and folders will reside in /root. 

Once this is done, follow the steps below to successfully run cornucopia

1.) Make the post-gres database, run all the command below sequentially to create the database.

    a.) service postgresql start
    b.) su postgres
    c.) psql
    d.) create database db;
    e.) create user anon with encrypted password 'admin';
    f.) grant all privileges on database db to anon;
    
to quit psql use \q and to quit postgres use exit.

1.) Run the server
Open a new screen to run the server in by typing "screen". This will take you to a new screen. 
Go the the fitness_wrapper directory and type the following command in order to deply the server.
Note that we are using port 5001 here because that is the one that was exposed in the docker file.
Also note that we are using the function hash uniform weight server but to used another server out of the many that run different fitness function just replace the server .py file and run it instead.

    a.) python3 server_function_hash_uniform_weight.py /root/fitness_wrapper/uploaded_files/ 5001
    
When you have tun the server it will show something like this: 
 * Serving Flask app 'server_function_hash_uniform_weight' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://xxx.xx.x.x:5001/ (Press CTRL+C to quit)
 
Copy the IP address, http://xxx.xx.x.x:5001/ for example above and close the screen with ctrl A + D. 
paste this IP address in the randollvm.config file in the SERVER_URL field. This is ther address where cornucopia will send the generated files.
   


2.) Choose which architecture you are fuzzing LLVM for, you can choose from the following 4 architectures. 
    
    a.) x86-64
    b.) x86
    c.) arm 
    d.) mips

4.) Run option parser to get the architecture specific optimization options 
We need to run this to get the correct optimization flags for the architecture chosen. 
If you choose mips for example run the following command in the /root directory where optionParser.py resides to get all the target specific options which will be outputted in the file "option_list.txt".

    a.) python3 optionParser.py options_list.txt mips
    
change mips in the command above with the architecture of choice

5.) Modify randollvm.config file in automation_scripts as per need.
Modify this file in the folder automation_scripts to fine tune of the options, for instance the iterations to fuzz, threads to use, fuzzing time if you need to use time instead of iterations. Change the architecture from the ones mentioned above as well. Depending on which server you deployed enter the name of the server file name. Also, if you just want to fuzz a single bitcode file from the multiple ones that are available in afl_source then change the name to that file for the option SOURCE in this file. 


6.) Sometimes AFL++ complains about CPU governer so it would it a good idea to run the following commnind on your host machine outside docker.

    a.) sudo echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

7.) Finally running cornucopia with your setting

Go to the automation_scripts folder and run the following command for help on Cornucopia. 

    a.) python3 run_fuzz.py --help 

you need to provide the fuzz mode (1 for a single file in parallel and 0 for all files in afl_sources in parallel)
you also need to provide the config file.

for example you can run the following command to run cornucopia for all files in parallel where each source in fuzzed on a single core using the following, make sure that you run this command in another screen.

    b.) python3 run_fuzz.py -m 0 randollvm.config

To run cornucopia in parallel mode for just one source file use the following command, when using this mode cornucopia will use the source file that was entered in the config file.

    c.) python3 run_fuzz.py -m 1 randollvm.config
    
8.) To make sure that everything is running well, check the screen where you deployed the server and you should see files being sent to it. You can also check the afl++ output in the "llvm_afl_fuzz_crashes" directory. If for some reason you don't see a server output check for logs in the "llvm_afl_fuzz_crashes" to see what happened and why afl++ did not run. 

9.) The generated file will start getting populated in the "fitness_wrapper/uploaded_files/x86_64" folder. Each source will have its own folder and all the unique assembly files will be inside that folder.

10.) The server logs can also be accessed via postgresSql to see what new files were entered in the database with the corresponding time stamp. 


