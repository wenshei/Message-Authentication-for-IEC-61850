#!/bin/bash

DIR=$(pwd)
echo $DIR

# Build LoMoS
cd ${DIR}/LoMoS
./compile.sh

# Build CMMA
cd ${DIR}/CMMA
cmake -S. -Bbuild
cmake --build build
