from genericpath import isfile
import threading
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
import uuid
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
    timeStamp       =db.Column(db.Text())
    
    def __init__(self, architecture, binary_name, binary_hash, file_path, functionHashes, timeStamp):
        self.architecture = architecture
        self.binary_name = binary_name
        self.binary_hash = binary_hash
        self.file_path = file_path
        self.functionHashes = functionHashes
        self.timeStamp      = timeStamp

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
        hashRegEx = re.compile(r'net hash: (\d+)')
        hashFound = hashRegEx.findall(str(request.data))
        if(hashFound):
            hashNumber = hashFound[-1]
        else:
            print("Could not find any global hash so returning a 0.0 weight")
            return str(0.0)

        print("Hash that the server saw is " + str(hashNumber))

        functionRegEx = re.compile(r'function hash: (\d+)')
        fuctionHashes = functionRegEx.findall(str(request.data))

        #Find the architecture name from the assembly file
        architectureFinder = re.compile(r'The architecture name for the current machine is: (\w+)')
        architectureContanintString = architectureFinder.search(str(request.data))
        if architectureContanintString == None:
            print("Empty File sent to server")
            return str(0.0)
        architectureName = str(architectureContanintString[1])

        #set the return value to 0
        return_value = 0.0
        
        if (AsmFiles.query.filter_by(architecture=architectureName, binary_name=filename, binary_hash=hashNumber).all() == []):

            print("--------------------------------------")
            print("--------------------------------------")
            print("-----------found new file-------------")
            print("--------------------------------------")
            print("--------------------------------------")
            print("--------------------------------------")
            
            #architectureName is obtained from the ASM File, the LLVM version we are using is modified to 
            #output the architecture name which is found using a regex in the sever

            function_hash_string = ""
            for hashes in fuctionHashes:
                function_hash_string = function_hash_string + hashes + "," 
            
            #This nested for loop checks to see if any function that is seen is different or not
            #If it is different, we need to use it to compute the weight of the binary
            
            isFunctionDifferent = [1.0]*len(fuctionHashes)

            #go through the complete database to see if there are any different function hashes 
            Database = AsmFiles.query.filter_by(architecture=architectureName, binary_name=filename).all()             
            for items in Database:
                items_dict = items.__dict__
                function_hashes = str(items_dict['functionHashes'])
                for i in range(len(fuctionHashes)):
                    if fuctionHashes[i] in function_hashes:
                        isFunctionDifferent[i] = 0.0
            
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
            
            filename_saved = hashlib.sha256(request.get_data(as_text=True).encode("utf-8")).hexdigest() 
            file_path = DOWNLOADS + "/" + str(architectureName) + "/" + str(filename) + "/" + str(filename_saved) + ".s" 
            if (  os.path.isfile(file_path) == False ):
                with open(os.path.join(file_path), "wb") as fp:
                    fp.write(request.get_data())


            dateTimeObj = datetime.now()
            timestampStr = dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S.%f)")
            
            asm_file = AsmFiles(architectureName, filename, hashNumber, file_path, function_hash_string, timestampStr)
            
            
            lock.acquire()

            if (AsmFiles.query.filter_by(architecture=architectureName, binary_name=filename, binary_hash=hashNumber).all() == []):
                db.session.add(asm_file)
                db.session.commit()

            lock.release()           


            flash('Asm file successfully added')
            print('Added a new Asm File to the database')

            #calculate the final weight using the individual function weights and if the function is different or not
            final_calculated_weight = 0.0
            for function_index in range(len(isFunctionDifferent)):
                final_calculated_weight = final_calculated_weight + isFunctionDifferent[function_index]   

            if(len(isFunctionDifferent) > 0):
                return_value = final_calculated_weight / len(isFunctionDifferent)
            print("The weight that was returned the server is: " + str(return_value))
        
    #return the calculated weight, is weight is 0 then the binary is not interesting, otherwise an integer weight is returned
    return str(return_value)

#just a method for the home page of the server
@app.route('/', methods=["POST", "GET"])
def home():
   return 'This is a server for diffing and storing assembly files!'



if __name__ == '__main__':    
    
    #initialize the sql-alchemy data, 
    db.create_all()
    #run the app
    app.run(host=os.getenv('IP', '0.0.0.0'), port=int(os.getenv('PORT', PORT)), debug=False, threaded=True)
