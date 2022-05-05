import os

numFiles = 5
random_byte = 0;

#Enter some random number for the number of options available, this doesn't matter as these
#Inputs just serve as some original seeds
numOptimizations = 1000

if not os.path.isdir("inputs"):
    os.mkdir("inputs")

for i in range(numFiles):
    outFile = open("inputs/optionmap" + str(i), 'wb')
    for j in range(numOptimizations):
        random_byte = os.urandom(1)
        while(random_byte == b'\x00'):
            random_byte = os.urandom(1)
        outFile.write(random_byte)
    outFile.close()
