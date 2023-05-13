#Download base image ubuntu 20.04
FROM ubuntu:20.04
# set a directory for the the source code
WORKDIR /root

# LABEL about the custom image
LABEL maintainer=""
LABEL version="0.1"
LABEL description="This is a Docker image for Cornucopia"

# Disable Prompt During Packages Installation
ARG DEBIAN_FRONTEND=noninteractive

# Update Ubuntu Software repository
RUN apt-get update && apt-get -y upgrade

RUN apt-get update && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    automake \
    cmake \
    meson \
    ninja-build \
    bison flex \
    build-essential \
    git \
    python3 python3-dev python3-setuptools python-is-python3 \
    libtool libtool-bin \
    libglib2.0-dev \
    wget vim jupp nano bash-completion less \
    apt-utils apt-transport-https ca-certificates gnupg dialog \
    libpixman-1-dev \
    gnuplot-nox \
    && rm -rf /var/lib/apt/lists/*

RUN echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-12 main" >> /etc/apt/sources.list && \
    wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

RUN echo "deb http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu focal main" >> /etc/apt/sources.list && \
    apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 1E9377A2BA9EF27F

RUN apt-get update && apt-get full-upgrade -y && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    gcc-10 g++-10 gcc-10-plugin-dev gdb lcov \
    clang-12 clang-tools-12 libc++1-12 libc++-12-dev \
    libc++abi1-12 libc++abi-12-dev libclang1-12 libclang-12-dev \
    libclang-common-12-dev libclang-cpp12 libclang-cpp12-dev liblld-12 \
    liblld-12-dev liblldb-12 liblldb-12-dev libllvm12 libomp-12-dev \
    libomp5-12 lld-12 lldb-12 llvm-12 llvm-12-dev llvm-12-runtime llvm-12-tools


RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 0
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-10 0

RUN apt install -y software-properties-common
RUN apt-get install -y apt-utils

#install vim to view files
RUN apt-get update && apt-get install -y vim && apt-get install -y nmap

#Install Python Dependencies
#Server side dependencies
RUN apt update
RUN apt install -y python3-pip
RUN pip3 install pyGenericPath
RUN pip3 install thread6
RUN pip3 install flask
RUN pip3 install regex
RUN pip3 install flask-peewee
RUN pip3 install DateTime
RUN pip3 install peewee
RUN pip3 install Flask-SQLAlchemy
RUN pip3 install Flask-Migrate
RUN pip3 install uuid

#Automation side dependencies
RUN pip3 install future
RUN pip3 install argparse
RUN pip3 install Pebble
RUN pip3 install futures
RUN pip3 install multiprocessing-logging
RUN pip3 install python-csv

#Install postgresSQL
RUN apt update
RUN apt install -y postgresql postgresql-contrib
RUN service postgresql start

#Install psycopg2
RUN apt-get update
RUN apt-get install -y libpq-dev python-dev
RUN pip3 install psycopg2

#Install curl.h header
RUN apt-get install -y libcurl4-openssl-dev


#Install Cross Architecture specific packages
#Common packages
RUN apt-get update
RUN apt-get install -y build-essential
RUN apt-get install -y binutils-multiarch
RUN apt-get install -y ncurses-dev
RUN apt-get install -y alien 
RUN apt-get install -y bash-completion
RUN apt-get install -y screen
RUN apt-get install -y psmisc

#for  monitoring system usage, good to install htop
RUN apt-get install -y htop                     

#X86-32
RUN apt-get install -y gcc-multilib g++-multilib libc6-dev-i386

#ARM
RUN apt-get install -y gcc-arm-linux-gnueabi

#MIPS
RUN apt-get install -y --install-recommends gcc-mips-linux-gnu
#RUN ln -s /usr/bin/mips-linux-gnu-gcc-4.7 /usr/bin/mips-linux-gnu-gcc    ### This was needed if gcc 4.7 for mips was installed but now seems like package name is different


#Make some important directories
RUN mkdir llvm_afl_fuzz_crashes 
RUN mkdir gcc_afl_fuzz_crashes
RUN mkdir outputs
RUN mkdir inputs
RUN mkdir assembly_folder

# copy all the files to the container
COPY . . 

#set the llvm config version
ENV LLVM_CONFIG=llvm-config-12
#we don't really care about crashes
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

#build AFL++
RUN cd AFLplusplus && \ 
    make CC=`which gcc` CXX=`which g++` -j16 distrib && \
    make CC=`which gcc` CXX=`which g++` install

#Go back to the root directory
RUN cd ../.

#Installation for LLVM version
RUN cd HashEnabledLLVM && \
    mkdir build && \
    cd build && \
    cmake -G "Unix Makefiles" -DCMAKE_C_COMPILER=clang-12 -DCMAKE_CXX_COMPILER=clang++-12 -DLLVM_TARGETS_TO_BUILD="ARM;X86;Mips" -DLLVM_ENABLE_PROJECTS="clang;lldb" -DLLVM_USE_LINKER=gold -DCMAKE_BUILD_TYPE=Release ../llvm && \ 
    make install-llvm-headers && \
    make -j 8

#Go back to the root directory
RUN cd ../../.

#Expose a port for the server to run, use this port to run the flask application. 
EXPOSE 5001

#Some common commands to help the user
RUN python3 optionMap.py
RUN make

CMD ["bash"]
