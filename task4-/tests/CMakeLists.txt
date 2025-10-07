# add_executable(bignum_bench bignum_bench.cpp)
# target_link_libraries(bignum_bench PRIVATE bignum)
# if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
# 	target_compile_options(bignum_bench PRIVATE -O3 -mavx2)
# endif()

# Ensure GoogleTest is available for unit tests (provides gtest_main)
find_package(GTest REQUIRED)

add_executable(shamir_test shamir_test.cpp)
target_include_directories(shamir_test PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
target_link_libraries(shamir_test PRIVATE crypto_lib_boost)
add_test(NAME shamir_test COMMAND shamir_test)

add_executable(elgamal_test elgamal_test.cpp)
target_include_directories(elgamal_test PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
target_link_libraries(elgamal_test PRIVATE crypto_lib_boost)
add_test(NAME elgamal_test COMMAND elgamal_test)

add_executable(elgamal_signature_test elgamal_signature_test.cpp)
target_include_directories(elgamal_signature_test PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
target_link_libraries(elgamal_signature_test PRIVATE crypto_lib_boost GTest::gtest_main)
add_test(NAME elgamal_signature_test COMMAND elgamal_signature_test)

add_executable(gost_signature_test gost_signature_test.cpp)
target_include_directories(gost_signature_test PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
target_link_libraries(gost_signature_test PRIVATE crypto_lib_boost GTest::gtest_main)
add_test(NAME gost_signature_test COMMAND gost_signature_test)

add_executable(dsa_signature_test dsa_signature_test.cpp)
target_include_directories(dsa_signature_test PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
target_link_libraries(dsa_signature_test PRIVATE crypto_lib_boost GTest::gtest_main)
add_test(NAME dsa_signature_test COMMAND dsa_signature_test)

add_executable(rsa_test rsa_test.cpp)
target_include_directories(rsa_test PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
target_link_libraries(rsa_test PRIVATE crypto_lib_boost)
add_test(NAME rsa_test COMMAND rsa_test)

add_executable(shamir_negative_test shamir_negative_test.cpp)
target_include_directories(shamir_negative_test PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
target_link_libraries(shamir_negative_test PRIVATE crypto_lib_boost)
add_test(NAME shamir_negative_test COMMAND shamir_negative_test)

add_executable(vernam_test vernam_test.cpp)
target_include_directories(vernam_test PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
target_link_libraries(vernam_test PRIVATE crypto_lib_boost)
add_test(NAME vernam_test COMMAND vernam_test)

add_executable(vernam_alice_bob_test vernam_alice_bob_test.cpp)
target_include_directories(vernam_alice_bob_test PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
target_link_libraries(vernam_alice_bob_test PRIVATE crypto_lib_boost)
add_test(NAME vernam_alice_bob_test COMMAND vernam_alice_bob_test)

add_executable(rsa_signature_test rsa_signature_test.cpp)
target_include_directories(rsa_signature_test PRIVATE ${CMAKE_SOURCE_DIR}/crypto_lib_boost/include)
target_link_libraries(rsa_signature_test PRIVATE crypto_lib_boost GTest::gtest_main)
add_test(NAME rsa_signature_test COMMAND rsa_signature_test)

# if (ENABLE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
# 	target_compile_options(bignum_tests PRIVATE --coverage -O0)
# 	target_link_options(bignum_tests PRIVATE --coverage)
# endif()