#ifndef ELGAMAL_CIPHER_HPP
#define ELGAMAL_CIPHER_HPP

#include "crypto_lib_boost/bignum.hpp"
#include <vector>
#include <string>
#include <filesystem>

namespace elgamal_cipher {

struct ElGamalKeys {
    BigInt p; // prime modulus
    BigInt g; // generator
    BigInt c_b; // public exponent (g^xb mod p)
    BigInt d_b; // private exponent xb
};

// Generate keys: bit_length for prime p, returns p,g,c_b,d_b
ElGamalKeys generate_keys(int bit_length = 512);

// Encrypt and decrypt using the same file-oriented API as shamir_cipher
// encrypt: takes raw bytes and returns a string representation (space-separated BigInt numbers)
std::string encrypt(const std::vector<unsigned char>& data, const BigInt& p, const BigInt& g, const BigInt& c_b);

// decrypt: accepts encrypted string and private exponent d_b
std::vector<unsigned char> decrypt(const std::string& encrypted_data, const BigInt& p, const BigInt& d_b);

// Save/load keys to/from files (public: .pub, private: .key) using base64 text values like shamir
void save_keys_to_files(const ElGamalKeys& keys, const std::string& base_filename);
ElGamalKeys load_public_keys(const std::filesystem::path& pub_key_path);
ElGamalKeys load_private_keys(const std::filesystem::path& priv_key_path);

} // namespace elgamal_cipher

#endif // ELGAMAL_CIPHER_HPP
