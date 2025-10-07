#include <gtest/gtest.h>
#include "crypto_lib_boost/signature_interface.hpp"
#include <fstream>

TEST(DSASignatureTests, SignAndVerify) {
    std::string fname = "dsa_test_file.txt";
    std::ofstream f(fname); f << "hello dsa"; f.close();
    auto kp = signature::generate_dsa_keys(256);
    auto sig = signature::dsa_sign_file(kp.priv_path, fname);
    ASSERT_FALSE(sig.empty());
    EXPECT_TRUE(signature::dsa_verify_file(kp.pub_path, fname, sig));
    if (!sig.empty()) sig.push_back(0);
    EXPECT_FALSE(signature::dsa_verify_file(kp.pub_path, fname, sig));
}
