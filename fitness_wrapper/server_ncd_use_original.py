from genericpath import isfile
import threading
#from typing import final
from flask import Flask, request, abort, jsonify
import os
import hashlib
import re
import sys
from flask_peewee.db import Database
import datetime
from peewee import *
from flask import Flask, request, flash, url_for, redirect, render_template
from flask_sqlalchemy import SQLAlchemy
from threading import Lock, Thread
import lzma                             #compression library for calculating the normalized compression distance
import lief
from datetime import datetime

#change this path to the place where you want you files to be uploaded, .s files (files are uploaded to the local machine)
if len(sys.argv) < 3:
    print("Usage: " +  sys.argv[0] + " <downloads_dir> <port_to_deploy_server>")
    sys.exit(1)

DOWNLOADS = sys.argv[1]
PORT = sys.argv[2]

#make the download directory if its not already present
if not os.path.exists(DOWNLOADS):
    os.makedirs(DOWNLOADS)

if not os.path.exists(DOWNLOADS + "/original_sources/"):
    os.makedirs(DOWNLOADS + "/original_sources/")

#making an sql-alchemy database using postgres
app = Flask(__name__)

#for the following setting "SQLALCHEMY_DATABASE_URI"
#create a postgres server and connect to it using pgAdmin
#then in the pgAdmin application create a database for for the server
#set the variable as "postgresql://<username>:<password>@<server>:5432/<db_name>"
#here username for me is "anon", password is "admin", database name is db
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://anon:admin@localhost/db'
app.config['SECRET_KEY'] = "admin"
app.config['SQLALCHEMY_POOL_SIZE'] =  100
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#instantiate the sql-alchemy database.
db = SQLAlchemy(app)
lock = Lock()

#Define class AsmFiles that holds the architecure name, binary file name, hash name and the contects of the asm files.
class AsmFiles(db.Model):
    architecture    =db.Column(db.Text(), primary_key = True)
    binary_name     =db.Column(db.Text(), primary_key = True)
    binary_hash     =db.Column(db.Text(), primary_key = True)
    file_path       =db.Column(db.Text())
    functionHashes  =db.Column(db.Text())
    functionSizes   =db.Column(db.Text())
    timeStamp       =db.Column(db.Text())  
    
    def __init__(self, architecture, binary_name, binary_hash, file_path, functionHashes, functionSizes, timeStamp):
        self.architecture = architecture
        self.binary_name = binary_name
        self.binary_hash = binary_hash
        self.file_path = file_path
        self.functionHashes = functionHashes
        self.functionSizes = functionSizes
        self.timeStamp = timeStamp

def get_text_sec(raw_data, filename):
    binary = lief.parse(raw=raw_data, name=filename)
    text = binary.get_section(".text")

    header = binary.header
    arch = header.machine_type
    architectureName = "{}".format(arch).split(".")[-1]
    return bytes(text.content), architectureName

@app.route("/upload/<filename>", methods=["POST", "GET"])
def post_file(filename):
    
    if ".s" in filename:
        filename = filename.replace('.s', '')
    
    #trying to upload a file to the flask server    
    if "/" in filename:
        #Return 400 BAD REQUEST
        abort(400, "trying to add subdirectory, not allowed!")

    if request.method == 'POST':
        
        #find the hash from the contents of the asm file data itself.
        #hashRegEx = re.compile(r'net hash: (\d+)')
        #hashFound = hashRegEx.findall(str(request.data))
        #hashNumber = hashFound[-1]
        #print("Hash that the server saw is " + str(hashNumber))
	
        text_section, architectureName = get_text_sec(request.get_data(), filename)

        hashNumber = hashlib.sha256(text_section).hexdigest()

        #hashNumber = str(lzma.compress(bytes(request.data)))                #hash is not the compression data

        #print(str(hashNumber))

        #exit()
        
        #fuctionHashes = hashFound[0:(len(hashFound) - 2)] #omit the last function hash, as that is the net hash of all the functions
        
        #functionSizeFinder = re.compile(r'function size: (\d+)')
        #functionSizesFound = functionSizeFinder.findall(str(request.data))
        
        #Calculate the score for the difference in binaries using the function sizes

        #Find the architecture name from the assembly file
        #architectureFinder = re.compile(r'The architecture name for the current machine is: (\w+)')
        #architectureContanintString = architectureFinder.search(str(request.get_data(as_text=True)))
        #architectureName = str(architectureContanintString[1])

        #set the return value to 0
        return_value = 0.0
        
        if (AsmFiles.query.filter_by(architecture=architectureName, binary_name=filename, binary_hash=hashNumber).all() == []):
            
            #architectureName is obtained from the ASM File, the LLVM version we are using is modified to 
            #output this the architecturer name which is found using a regex in the sever

            CurrentFileCompression = lzma.compress(text_section)       

            function_hash_string = ""
            #for hashes in fuctionHashes:
                #function_hash_string = function_hash_string + hashes + ","
            
            function_sizes_string = ""
            #for function_sizes in functionSizesFound:
                #function_sizes_string = function_sizes_string + function_sizes + ","  
            
            #This nested for loop checks to see if any function that is seen is different or not
            #If it is different, we need to use it to compute the weight of the binary
            
            #isFunctionDifferent = [1.0]*len(fuctionHashes)

            #go through the complete database to see if there are any different function hashes 
            #ncd_scores = []
            #Database = AsmFiles.query.filter_by(architecture=architectureName, binary_name=filename).all()             
            #for items in Database:
            #    items_dict = items.__dict__
            #    binary_hash_seen = items_dict['binary_hash']

            #change this path so that is accesses the -O0 file all the time
            file_path_O0 = DOWNLOADS + "/original_sources" + "/" + str(filename) 

            file_data_O0 = open(os.path.join(file_path_O0), "rb").read()

            current_file_text, arch_name = get_text_sec(file_data_O0, filename)
            file_compression_O0 = lzma.compress(current_file_text)               
            data_concatenated = current_file_text +  text_section

            combined_compression = lzma.compress(data_concatenated)            
            ncd = (len(combined_compression) - min(len(file_compression_O0), len(CurrentFileCompression))) / max(len(file_compression_O0), len(CurrentFileCompression))             
            #print(ncd)       
            #ncd_scores.append(ncd)            
            #if(len(ncd_scores) > 0):
            return_value = ncd        
            
            #once we check if any function is different or not we can just add the new asm file to the database
            if ".s" in filename:
                filename = filename.replace('.s', '')
            
            #if the architecture sub folder is not created then create this subfolder 
            if ( (os.path.isdir(DOWNLOADS + "/" + str(architectureName) )) == False ):
                os.mkdir( DOWNLOADS + "/" + str(architectureName) )

            #if the hash of this particular source asm is not seen, then it will create the new folder for the source
            #and then write the data as well
            if ( (os.path.isdir(DOWNLOADS + "/" + str(architectureName) + "/" + str(filename) )) == False ):
                os.mkdir( DOWNLOADS + "/" + str(architectureName) + "/" + str(filename) )
            
            file_path = DOWNLOADS + "/" + str(architectureName) + "/" + str(filename) + "/" + str(hashNumber) 
            if (  os.path.isfile(file_path) == False ):
                with open(os.path.join(file_path), "wb") as fp:
                    fp.write(request.get_data())
                    

            dateTimeObj = datetime.now()
            timestampStr = dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S.%f)")

            asm_file = AsmFiles(architectureName, filename, hashNumber, file_path, function_hash_string, function_sizes_string, timestampStr)
            
            
            lock.acquire()

            if (AsmFiles.query.filter_by(architecture=architectureName, binary_name=filename, binary_hash=hashNumber).all() == []):
                db.session.add(asm_file)
                db.session.commit()

            lock.release()           


            flash('Asm file successfully added')
            print('Added a new Asm File to the database')
            print("The weight that was returned the server is: " + str(return_value))
            
            # #calculate the total sizes of the hashes
            # #total_size = 0.0
            # #for items in functionSizesFound:
            # #    total_size += float(items)

            # #calculate the weight of each function based on the size of the function
            # #weights = []
            # #for func_size in functionSizesFound:
            # #    if float(total_size) == 0.0:
            # #        intermediate_weight = 0.0
            # #    else:
            # #        intermediate_weight = float(func_size)/float(total_size)
            #     #subtract the weight from 1 since we want smaller functions to have larget weight
            # #    intermediate_weight = 1.0 - intermediate_weight
            # #    weights.append(intermediate_weight)            

            # #calculate the final weight using the individual function weights and if the function is different or not
            # #final_calculated_weight = 0.0
            # #for function_index in range(len(isFunctionDifferent)):
            # #    final_calculated_weight = final_calculated_weight + isFunctionDifferent[function_index] * weights[function_index]         

            # #return_value = final_calculated_weight
            # print("The weight that was returned the server is: " + str(return_value))
            #print(return_value) 
    #return the calculated weight, is weight is 0 then the binary is not interesting, otherwise an integer weight is returned
    return str(return_value)

#just a method for the home page of the server
@app.route('/', methods=["POST", "GET"])
def home():
   return 'This is a server for diffing and storing assembly files!'

#method to download the files from the databse into the local directory
# no longer needed
#@app.route("/download", methods=["POST"])
#def download_file():
#    
#    #this gets all the files in the database
#    DataBase = AsmFiles.query.all()
#    
#    #for all the items in the database, write them to the local server
#    for items in DataBase:
#        items_dict = items.__dict__
#        architecture_name = items_dict['architecture']
#        hash_key = items_dict['binary_hash']
#        binary_name = items_dict['binary_name']
#        
#        #just in case the binary name has a suffix of an asm, remove it
#        if ".s" in binary_name:
#            binary_name = binary_name.replace('.s', '')
#        
#        #if the architecture sub folder is not created then create this subfolder 
#        if ( (os.path.isdir(DOWNLOADS + "/" + str(architecture_name) )) == False ):
#            os.mkdir( DOWNLOADS + "/" + str(architecture_name) )
#
#        #if the hash of this particular source asm is not seen, then it will create the new folder for the source
#        #and then write the data as well
#        if ( (os.path.isdir(DOWNLOADS + "/" + str(architecture_name) + "/" + str(binary_name) )) == False ):
#            os.mkdir( DOWNLOADS + "/" + str(architecture_name) + "/" + str(binary_name) )
#        
#        if ( (os.path.isfile(DOWNLOADS + "/" + str(architecture_name) + "/" + str(binary_name) + "/" + str(hash_key) + ".s" )) == False ):
#            with open(os.path.join(DOWNLOADS + "/" + str(architecture_name) + "/" + str(binary_name) + "/" + str(hash_key) + ".s"), "w") as fp:
#                fp.write(items_dict['file_data'])
#    
#    #Return 201 CREATED
#    return "", 201


if __name__ == '__main__':    
    
    #initialize the sql-alchemy data, 
    db.create_all()
    #run the app
    app.run(host=os.getenv('IP', '0.0.0.0'), port=int(os.getenv('PORT', PORT)), debug=False, threaded=True)
