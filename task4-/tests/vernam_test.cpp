// Simple Vernam roundtrip test
#include <iostream>
#include <vector>
#include <string>
#include "crypto_lib_boost/vernam_cipher.hpp"

int main() {
    std::cout << "Vernam cipher test (Boost backend)...\n";
    auto keys = vernam_cipher::generate_keys(32);
    std::vector<unsigned char> data = {'H','e','l','l','o',' ', 'V','e','r','n','a','m'};
    // encrypt expects (p,g, sender_private_xa, receiver_public_pb)
    auto enc = vernam_cipher::encrypt(data, keys.p, keys.g, keys.xa, keys.pb);
    // decrypt expects (p,g, receiver_private_xb, sender_public_pa)
    auto dec = vernam_cipher::decrypt(enc, keys.p, keys.g, keys.xb, keys.pa);
    if (dec == data) {
        std::cout << "[SUCCESS] Vernam roundtrip OK\n";
        return 0;
    } else {
        std::cerr << "[FAIL] Vernam roundtrip mismatch\n";
        std::cerr << "Original: ";
        for (char c : data) std::cerr << c;
        std::cerr << "\nDecrypted: ";
        for (char c : dec) std::cerr << c;
        std::cerr << std::endl;
        return 2;
    }
}
