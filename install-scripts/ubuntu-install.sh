#!/bin/bash
#
# panda-deploy.sh
#

#
# ubuntu-install.sh will install the latest version of PANDA and associated
# API framework and packages for Ubuntu.
#
# The PANDA github repository: https://github.com/panda-net/panda
#
# Copyright (c) 2021 SiPanda Inc.
#

#
# allow the install script to input as an argument the path to install the PANDA platform.
#
# Prerequisites:
#

#
# Basics development prerequisites on Ubuntu 20.10 or later.
#
# Ubuntu 20.10 or later and Linux 5.8 or later
#   - check for Ubuntu 20.10 or 21.x or higher
#   Ubuntu 20.10 includes the 5.8 Linux kernel
#   Ubuntu 21.04 includes the 5.11 Linux kernel
#

if [ $# -eq 0 ] || [ $1 = "-h" ] || [ $1 = "--help" ]
  then
    echo "Usage: [option...] {directory}"
    echo "   -p, --path                  Create all directories in path "
    echo "   -h, --help                  Shows this helpful information "
    echo
    exit
fi
#
# create directory with a path - get PANDA source directory and create it.
#
if [ $1 = "-p" ] || [ $1 = "--path" ]
then
    # Top level directoy or another high level directory
    TOPDIR=$2
    mkdir -p "$2" &>/dev/null
    if [ $? -gt 0 ]
      then
        echo "There was a problem creating your directory: " $2
        exit
    fi
    cd "$2" &>/dev/null
    if [ $? -gt 0 ]
      then
        echo "Unable to change into that directory."
        exit
    fi
else
    # Top level directoy or another high level directory
    fullpath=`pwd`
    TOPDIR=$fullpath/$1
    # create directory in this location
    mkdir -p "$1" &>/dev/null
    if [ $? -gt 0 ]
    then
	echo "There was a problem creating your directory: " $1
	exit
    fi
    cd "$1" &>/dev/null
    if [ $? -gt 0 ]
    then
	echo "Unable to change into that directory."
	exit
    fi
fi


echo "***********************************************************************************"
echo "By default the PANDA parser framework install script requires Ubuntu 20.10 or later"
echo "You are running on : "
grep -oP 'VERSION_ID="\K[\d.]+' /etc/os-release
while true; do
    read -p "Do you wish to continue with the install?" yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

echo ""
echo "Installing prerequisites ..."
echo "****************************"
echo ""

sudo apt-get install -y build-essential gcc-multilib pkg-config bison flex
sudo apt-get install -y libboost-all-dev libpcap-dev

# For creating graph visualizations from PANDA parser

echo ""
echo "Installing packages for graph visualizations from Pander Parser ..."
echo "*******************************************************************"
echo ""

sudo apt-get install -y graphviz

# eBPF related packages

echo ""
echo "Installing eBPF packages ..."
echo "****************************"
echo ""

sudo apt-get install -y libelf-dev clang llvm

# libbpf. This package not available in Ubuntu prior to 20.10 in which case
# the library can be build and installed

echo ""
echo "Installing libbpf (not available with Ubuntu prior to 20.10) ..."
echo "****************************************************************"
echo ""

sudo apt-get install -y libbpf-dev

echo ""
echo "Installing bpftool ..."
echo "**********************"
echo ""

# bpftool

sudo apt-get install -y linux-tools-$(uname -r)



echo ""
echo "Get latest version of panda-net/panda from github ..."
echo "*****************************************************"
echo ""

git clone  https://github.com/panda-net/panda

#SUBDIR=$TOPDIR/panda
SUBDIR=$TOPDIR/panda

# Install directoy
PANDADIR=$TOPDIR/install

echo ""
echo "Building and install PANDA ..."
echo "******************************"
echo ""

# Build and install PANDA.

cd $SUBDIR/src
./configure
make INSTALLDIR=$PANDADIR install

cd $SUBDIR/samples
make PANDADIR=$PANDADIR

