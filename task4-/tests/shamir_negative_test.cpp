#include "crypto_lib_boost/shamir_cipher.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include <iostream>
#include <vector>
#include <cassert>

int main() {
    try {
        std::cout << "Shamir negative test (Boost backend)..." << std::endl;
        auto keys = shamir_cipher::generate_keys(256);
        std::vector<unsigned char> original = {'t','e','s','t'};
        auto original_b64 = file_handler::to_base64(original);
        std::string enc = shamir_cipher::encrypt(original_b64, keys.p, keys.c_a, keys.c_b);

        // Construct wrong private keys by generating a fresh keypair
        auto wrong = shamir_cipher::generate_keys(256);
        // Attempt to decrypt with wrong private exponents
        auto decrypted = shamir_cipher::decrypt(enc, keys.p, wrong.d_a, wrong.d_b);
        // decrypted is base64 bytes - it should NOT equal original_b64
        if (decrypted == original_b64) {
            std::cerr << "[FAIL] Decryption succeeded with wrong keys (unexpected)" << std::endl;
            return 1;
        }
        std::cout << "[SUCCESS] Wrong-key decryption did not match original (expected)" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[PASS] Caught exception as expected: " << e.what() << std::endl;
        return 0;
    }
    return 0;
}
