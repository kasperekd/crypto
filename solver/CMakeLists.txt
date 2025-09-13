add_executable(solver main.cpp)

target_link_libraries(solver PRIVATE bignum)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
	target_compile_options(solver PRIVATE --coverage -O0)
	target_link_options(solver PRIVATE --coverage)
endif()