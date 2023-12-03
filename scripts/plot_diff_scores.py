import pandas as pd
import matplotlib.pyplot as plt
from pandas.core.base import DataError
import numpy as np
from datetime import datetime
import os
import re
import statistics
from statistics import mean
from statistics import median

#Architectires = ["bintuner", "cc", "cc_bintuner"]

Architectires = ["cc"]

#Architectires = ["bintuner_vs_copa"]

#Architectires = ["x64"]

Optimizations = ["O0", "O3"]

#Optimizations = ["all"]

#BaseFolder = "/home/vidush/Applications/"

BaseFolder = "/home/vidush/Applications/bindiff_cdf/"

#intersected_sources = "/home/vidush/Downloads/Sources/intersected.sources"
#insFile = open(intersected_sources, "r")
#orig_sources = insFile.readlines()
#orig_sources = [line.rstrip() for line in orig_sources]

for arch in Architectires:
    for opts in Optimizations:
        Folder = BaseFolder + "/" + arch + "/"  + opts

        DATA = {}

        for basedir, dirs, files in os.walk(Folder):

            for file in files:

                if ".result" in file:
                    log_file = str(basedir) + "/" + str(file)
                    print("Found log file " + log_file)
                    print("reading from the given log file")
                    
                    f = open(log_file, "r")
                    log_lines = f.readlines()

                    if len(log_lines) == 0:
                        continue

                    log_lines = [line.rstrip() for line in log_lines]
                    #print(log_lines)
                    
                    #sourceName = log_lines[0]
                    sourceName = file
                    print(sourceName)
                    fileHash   = log_lines[1]
                    print(fileHash)

                    #if sourceName in orig_sources:
                    
                    if sourceName not in DATA:
                        DATA[sourceName] = {}
                        
                    for line in log_lines:
                        if "similarity" in line:
                            print(line)
                            regex_sim = re.compile(r'.([+-]?([0-9]*[.])?[0-9]+).')
                            binDiffScore = regex_sim.findall(line)

                            if len(binDiffScore) == 0:
                                regex_sim = re.compile(r'similarity: ([0-9])')
                                binDiffScore = regex_sim.findall(line)

                            print(binDiffScore)
                            print(binDiffScore[0][0])
                            
                            #invert the bin-diff score
                            if fileHash not in DATA[sourceName]:
                                
                                try:
                                    DATA[sourceName][fileHash] = 1.0 - float(binDiffScore[0][0])
                                except:
                                    DATA[sourceName][fileHash] = 0.0


        print(DATA)

        average_diff = {}
        median_diff  = {}
        max_diff     = {}
        
        TOTAL_SCORES = []

        for programs in DATA:

            scores = list(DATA[programs].values())
            
            print(scores)
            TOTAL_SCORES.append(scores[0])

            average_diff[programs] = sum(scores) / len(scores)
            median_diff[programs]  = statistics.median(scores)
            max_diff[programs]     = max(scores)
       
        print()
        print()
        print("Max, Min, Average, Median of Scores: ")
        print("Max: " + str(max(TOTAL_SCORES)))
        print("Min: " + str(min(TOTAL_SCORES)))
        print("Mean: " + str(mean(TOTAL_SCORES)))
        print("Median: " + str(median(TOTAL_SCORES)))
        print("StdDev: " + str(statistics.stdev(TOTAL_SCORES)))
        print("....")
        print()

        cdf_data_avg    = {}
        cdf_data_median = {}
        cdf_data_max    = {}

        total_number_programs = 0

        bin_width = 0.05

        bins = []

        bins_val = 0.0

        while bins_val < 1.025:
            bins.append(round(bins_val, 3))
            bins_val += bin_width

        total_number_programs = len(list(DATA.keys()))

        al = list(average_diff.values())
        ml = list(median_diff.values())
        mxl = list(max_diff.values())

        for i in bins:
                
            count1 = len([j for j in al if j <= i])
            count2 = len([j for j in ml if j <= i])
            count3 = len([j for j in mxl if j <= i])

            if i not in cdf_data_avg:
                cdf_data_avg[i] = count1
            else:
                cdf_data_avg[i] += count1

            if i not in cdf_data_median:
                cdf_data_median[i] = count2
            else:
                cdf_data_median[i] += count2

            if i not in cdf_data_max:
                cdf_data_max[i] = count3
            else:
                cdf_data_max[i] += count3

        for key in cdf_data_avg:
            cdf_data_avg[key] = round((cdf_data_avg[key] / total_number_programs) * 100, 2)
            cdf_data_median[key] = round((cdf_data_median[key] / total_number_programs) * 100, 2)
            cdf_data_max[key] = round((cdf_data_max[key] / total_number_programs) * 100, 2)

        print(cdf_data_avg)
        print(cdf_data_median)
        print(cdf_data_max)

        with open(Folder + "/" + "avg.txt", 'w') as ff: 
            for key, value in cdf_data_avg.items(): 
                ff.write('%s,%s\n' % (key, value))

        with open(Folder + "/" +  "median.txt", 'w') as ff: 
            for key, value in cdf_data_median.items(): 
                ff.write('%s,%s\n' % (key, value))

        with open(Folder + "/" + "max.txt", 'w') as ff: 
            for key, value in cdf_data_max.items(): 
                ff.write('%s,%s\n' % (key, value))









