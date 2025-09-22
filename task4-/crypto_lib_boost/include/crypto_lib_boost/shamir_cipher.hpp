#ifndef SHAMIR_CIPHER_HPP
#define SHAMIR_CIPHER_HPP

#include "crypto_lib_boost/bignum.hpp"
#include <vector>
#include <string>
#include <filesystem>

namespace shamir_cipher {

struct ShamirKeys {
    BigInt p;
    BigInt c_a, d_a;
    BigInt c_b, d_b;
};

ShamirKeys generate_keys(int bit_length = 512);

std::string encrypt(const std::vector<unsigned char>& data, const BigInt& p, const BigInt& c_a, const BigInt& c_b);

std::vector<unsigned char> decrypt(const std::string& encrypted_data, const BigInt& p, const BigInt& d_a, const BigInt& d_b);

void save_keys_to_files(const ShamirKeys& keys, const std::string& base_filename);

ShamirKeys load_public_keys(const std::filesystem::path& pub_key_path);
ShamirKeys load_private_keys(const std::filesystem::path& priv_key_path);

} // namespace shamir_cipher

#endif // SHAMIR_CIPHER_HPP