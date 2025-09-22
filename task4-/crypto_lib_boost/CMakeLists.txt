add_library(crypto_lib_boost STATIC
    src/bignum.cpp
    src/file_handler.cpp
    src/prime_utils.cpp
    src/shamir_cipher.cpp
    src/elgamal_cipher.cpp  
    src/rsa_cipher.cpp
    src/vernam_cipher.cpp
)

target_include_directories(crypto_lib_boost PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)