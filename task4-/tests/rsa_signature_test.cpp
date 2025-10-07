#include <iostream>
#include <fstream>
#include "crypto_lib_boost/signature_interface.hpp"

int main() {
    std::cout << "RSA signature test...\n";
    // create a small file
    std::ofstream f("rsa_test_file.txt"); f << "Hello RSA"; f.close();

    auto keys = signature::generate_rsa_keys(512);
    auto sig = signature::rsa_sign_file(keys.priv_path, "rsa_test_file.txt");
    std::cout << "Signature bytes size: " << sig.size() << "\n";
    bool ok = signature::rsa_verify_file(keys.pub_path, "rsa_test_file.txt", sig);
    if (!ok) { std::cerr << "[FAIL] RSA verify failed\n"; return 2; }

    // negative: modify file
    std::ofstream f2("rsa_test_file.txt"); f2 << "Tampered"; f2.close();
    bool ok2 = signature::rsa_verify_file(keys.pub_path, "rsa_test_file.txt", sig);
    if (ok2) { std::cerr << "[FAIL] RSA verify should fail for tampered file\n"; return 3; }

    std::cout << "[SUCCESS] RSA signature tests OK\n";
    return 0;
}
