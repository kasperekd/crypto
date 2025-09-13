option(ENABLE_COVERAGE "Enable code coverage flags" OFF)
cmake_minimum_required(VERSION 3.15)

project(BignumCrypto CXX)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Всегда использовать -O3 для максимальной оптимизации
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
	add_compile_options(-O3)
endif()

enable_testing()

add_subdirectory(bignum)
add_subdirectory(solver)
add_subdirectory(tests)