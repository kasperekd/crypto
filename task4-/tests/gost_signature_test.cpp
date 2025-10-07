#include <gtest/gtest.h>
#include "crypto_lib_boost/signature_interface.hpp"
#include <fstream>

TEST(GostSignatureTests, SignAndVerify) {
    std::string fname = "gost_test_file.txt";
    std::ofstream f(fname); f << "hello gost"; f.close();
    auto kp = signature::generate_gost_keys(256);
    auto sig = signature::gost_sign_file(kp.priv_path, fname);
    ASSERT_FALSE(sig.empty());
    EXPECT_TRUE(signature::gost_verify_file(kp.pub_path, fname, sig));
    if (!sig.empty()) sig.push_back(0);
    EXPECT_FALSE(signature::gost_verify_file(kp.pub_path, fname, sig));
}
