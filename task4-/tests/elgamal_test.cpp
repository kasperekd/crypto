#include "crypto_lib_boost/elgamal_cipher.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include <iostream>
#include <vector>
#include <cassert>

int main() {
    try {
        std::cout << "ElGamal cipher test (Boost backend)..." << std::endl;
        auto keys = elgamal_cipher::generate_keys(256);
        std::vector<unsigned char> original = {'E','l','G','a','m','a','l','!'};
        std::string enc = elgamal_cipher::encrypt(original, keys.p, keys.g, keys.c_b);
        auto dec = elgamal_cipher::decrypt(enc, keys.p, keys.d_b);
        assert(dec == original);
        std::cout << "[SUCCESS] ElGamal roundtrip OK" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[FAIL] " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
