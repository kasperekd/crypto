option(ENABLE_COVERAGE "Enable code coverage flags" OFF)
cmake_minimum_required(VERSION 3.15)

project(BignumCrypto CXX)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
	add_compile_options(-O3 -march=native -funroll-loops -ffast-math -mavx2)
endif()

enable_testing()

add_subdirectory(bignum)
add_subdirectory(crypto_lib)
add_subdirectory(solver)
add_subdirectory(tests)