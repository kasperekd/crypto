add_library(crypto_lib_boost STATIC
    src/bignum.cpp
    src/file_handler.cpp
    src/prime_utils.cpp
    src/shamir_cipher.cpp
    src/elgamal_cipher.cpp  
    src/rsa_cipher.cpp
    src/vernam_cipher.cpp
    src/sha256.cpp
    src/rsa_signature.cpp
    src/elgamal_signature.cpp
    src/gost_signature.cpp
    src/dsa_signature.cpp
)

target_include_directories(crypto_lib_boost PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    target_link_libraries(crypto_lib_boost PUBLIC OpenSSL::Crypto)
endif()