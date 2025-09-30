#include "crypto_lib_boost/rsa_cipher.hpp"
#include <iostream>
#include <vector>
#include <cassert>

int main() {
    try {
        std::cout << "RSA cipher test (Boost backend)..." << std::endl;
        auto keys = rsa_cipher::generate_keys(128);
        std::vector<unsigned char> original = {'R','S','A','!'};
        std::string enc = rsa_cipher::encrypt(original, keys.n, keys.e);
        auto dec = rsa_cipher::decrypt(enc, keys.n, keys.d);
        assert(dec == original);
        std::cout << "[SUCCESS] RSA roundtrip OK" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[FAIL] " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
