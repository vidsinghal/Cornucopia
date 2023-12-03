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

bintuner_emulated = [20, 63,13,26,27,1,  148, 89,20, 135, 30, 39, 52, 18, 176, 59,  48, 9, 68, 15]
bintuner_original = [23, 38,64,43,53,23,  30, 48,81,  34, 52, 58, 46,111,  42, 39,  51,  54, 52, 27]
cornucopia_single = [74,268,21,28,45, 1,2488,320, 6,2138,111,512,154, 23,897,187,351,806,281,299]

width = 0.3

x = np.arange(len(list_x))

plt.bar(x-width, bintuner_emulated, width)
plt.bar(x,     bintuner_original, width)
plt.bar(x+width, cornucopia_single, width)

plt.xticks(x, list_x, rotation = 45)
plt.xlabel("Programs")
plt.ylabel("Number of Binaries")
plt.legend(["Cornucopia with bintuner", "Bintuner", "Cornucopia"], loc='upper left')
plt.savefig('binaryCount.pdf', format="pdf", bbox_inches="tight")

plt.show()

