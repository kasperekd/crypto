// Vernam integration test: simulate Alice and Bob exchange
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include "crypto_lib_boost/vernam_cipher.hpp"
#include "crypto_lib_boost/file_handler.hpp"

int main() {
    std::cout << "Vernam Alice-Bob integration test...\n";

    auto alice = vernam_cipher::generate_keys(64);
    vernam_cipher::save_keys_to_files(alice, "alice");

    auto alice_pub = vernam_cipher::load_public_keys("alice.pub");


    auto bob = vernam_cipher::generate_keys(64);
    bob.p = alice_pub.p;
    bob.g = alice_pub.g;
    bob.xa = vernam_cipher::generate_keys(64).xa;
    bob.pb = bignum::mod_exp(bob.g, bob.xa, bob.p);
    vernam_cipher::save_keys_to_files(bob, "bob");

    std::vector<unsigned char> data = {'T','e','s','t',' ','A','l','i','c','e'};
    auto enc = vernam_cipher::encrypt(data, alice.p, alice.g, alice.xa, bob.pb);

    auto dec = vernam_cipher::decrypt(enc, bob.p, bob.g, bob.xa, alice.pa);

    if (dec == data) {
        std::cout << "[SUCCESS] Alice->Bob Vernam roundtrip OK\n";
        std::filesystem::remove("alice.key");
        std::filesystem::remove("alice.pub");
        std::filesystem::remove("bob.key");
        std::filesystem::remove("bob.pub");
        return 0;
    } else {
        std::cerr << "[FAIL] Alice->Bob Vernam roundtrip mismatch\n";
        return 2;
    }
}
