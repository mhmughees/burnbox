cmake_minimum_required(VERSION 2.8)
project(burnbox)



#set(CMAKE_CXX_STANDARD 11)
#SET(CMAKE_CXX_COMPILER /usr/bin/clang)

set(CC "/usr/bin/g++")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_COMPILER ${CC})
set(CMAKE_CXX_COMPILER ${CC})
set(CMAKE_CXX_FLAGS "-Wall -Werror -Wno-unknown-pragmas -std=c++11")


message("compiler is: ${CC}")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" ${CMAKE_MODULE_PATH})

add_subdirectory(src)

#include(CTest)
#enable_testing()
#add_subdirectory(tests)


