add_library(bignum STATIC
    src/bignum.cpp
)

target_include_directories(bignum PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_options(bignum PRIVATE -mavx2)

if (ENABLE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(bignum PRIVATE --coverage -O0)
    target_link_options(bignum PRIVATE --coverage)
endif()