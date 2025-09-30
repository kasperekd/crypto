#ifndef RSA_CIPHER_HPP
#define RSA_CIPHER_HPP

#include "crypto_lib_boost/bignum.hpp"
#include <vector>
#include <string>
#include <filesystem>

namespace rsa_cipher {

struct RSAKeys {
    BigInt p;
    BigInt q;
    BigInt n; // p*q
    BigInt e; // public exponent
    BigInt d; // private exponent
};

// Generate RSA keypair with primes of bit_length each
RSAKeys generate_keys(int bit_length = 256);

// Encrypt/decrypt (demo per-byte RSA, not optimized for large files)
std::string encrypt(const std::vector<unsigned char>& data, const BigInt& n, const BigInt& e);
std::vector<unsigned char> decrypt(const std::string& encrypted_data, const BigInt& n, const BigInt& d);

// Save/load keys to/from files (.pub and .key) using base64 text format
void save_keys_to_files(const RSAKeys& keys, const std::string& base_filename);
RSAKeys load_public_keys(const std::filesystem::path& pub_key_path);
RSAKeys load_private_keys(const std::filesystem::path& priv_key_path);

} // namespace rsa_cipher

#endif // RSA_CIPHER_HPP
