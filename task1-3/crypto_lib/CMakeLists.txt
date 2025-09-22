add_library(crypto_lib STATIC
    src/crypto_lib.cpp
    src/discrete_log.cpp
    src/diffie_hellman.cpp
    src/prime_utils.cpp
)

target_include_directories(crypto_lib PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(crypto_lib PRIVATE -O3)
endif()

target_link_libraries(crypto_lib PUBLIC bignum)
