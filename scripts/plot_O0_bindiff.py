import matplotlib.pyplot as plt
import numpy as np

fig = plt.figure(figsize=(21, 9))

list_x = [
"openssl",
"482.sphinx3",
"453.povray",
"445.gobmk",
"464.h264ref",
"483.xalancbmk",
"429.mcf",
"433.milc",
"447.dealII",
"470.lbm",
"450.soplex",
"401.bzip2",
"456.hmmer",
"400.perlbench",
"462.libquantum",
"471.omnetpp",
"444.namd",
"473.astar",
"458.sjeng",
"coreutils",
]

bintuner_emulated = [46, 64,17,19,25,10,  72, 75,24, 122, 37, 79, 40, 12, 180, 48,  40, 144, 61, 99]
bintuner_original = [23, 38,64,43,53,23,  30, 48,81,  34, 52, 58, 46,111,  42, 39,  51,  54, 52, 50]
cornucopia_single = [96,542,22,32,59, 1,1868,588, 2,1838,307,819,229, 22,1394,478,4135,1439,317,362]

width = 0.3

x = np.arange(len(list_x))

plt.bar(x-width, bintuner_emulated, width)
plt.bar(x,     bintuner_original, width)
plt.bar(x+width, cornucopia_single, width)

plt.xticks(x, list_x, rotation = 45)
plt.xlabel("Programs")
plt.ylabel("Difference Score")
plt.legend(["Cornucopia with bintuner", "Bintuner", "Cornucopia"], loc='upper left')
plt.savefig('binaryCount.pdf', format="pdf", bbox_inches="tight")

plt.show()
