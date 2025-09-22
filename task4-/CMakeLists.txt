cmake_minimum_required(VERSION 3.10)
project(CryptoTasks4-7 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED)
if(Boost_FOUND)
    message(STATUS "Boost found. Version: ${Boost_VERSION_STRING}")
    include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "Boost not found! Please install Boost libraries.")
endif()

add_subdirectory(crypto_lib_boost)
add_subdirectory(solver)
add_subdirectory(tests)