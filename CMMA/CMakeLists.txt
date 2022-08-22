cmake_minimum_required(VERSION 3.0.0)
project(HuffTreeProject VERSION 0.1.0)

add_subdirectory(wolfssl-master)

add_library(CMMALib STATIC
    src/CryptoUtils.cpp
    src/HuffmanCode.cpp
    src/HuffmanNode.cpp
    src/HuffTree.cpp
    src/ProveVerify.cpp
    src/GenerateMessages.cpp
    src/GenerateNonces.cpp)

target_include_directories(CMMALib PUBLIC include)
target_link_libraries(CMMALib
    PUBLIC wolfssl)

add_executable(CMMA
    src/main.cpp
)

target_link_libraries(CMMA
    PUBLIC CMMALib
    PUBLIC crypto
    PUBLIC ssl)
