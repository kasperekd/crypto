#include <gtest/gtest.h>
#include "crypto_lib_boost/signature_interface.hpp"
#include <fstream>

TEST(ElGamalSignatureTests, SignAndVerify) {
    // prepare a small file
    std::string fname = "elgamal_test_file.txt";
    std::ofstream f(fname);
    f << "hello elgamal";
    f.close();

    // generate keys
    auto kp = signature::generate_elgamal_keys(256);

    // sign
    auto sig = signature::elgamal_sign_file(kp.priv_path, fname);
    ASSERT_FALSE(sig.empty());

    // verify (should pass)
    bool ok = signature::elgamal_verify_file(kp.pub_path, fname, sig);
    EXPECT_TRUE(ok);

    // tamper signature
    if (!sig.empty()) sig.push_back(0); // append a byte to corrupt the signature
    bool ok2 = signature::elgamal_verify_file(kp.pub_path, fname, sig);
    EXPECT_FALSE(ok2);
}
