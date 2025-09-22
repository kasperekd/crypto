#ifndef SHAMIR_CIPHER_HPP
#define SHAMIR_CIPHER_HPP

#include "crypto_lib_boost/bignum.hpp"
#include <vector>
#include <string>

namespace shamir_cipher {

struct ShamirKeys {
    BigInt p;
    BigInt c_a, d_a;
    BigInt c_b, d_b;
};

ShamirKeys generate_keys(int bit_length = 512);

std::string encrypt(const std::vector<unsigned char>& data, const BigInt& p, const BigInt& c_a, const BigInt& c_b);

std::vector<unsigned char> decrypt(const std::string& encrypted_data, const BigInt& p, const BigInt& d_a, const BigInt& d_b);

} // namespace shamir_cipher

#endif // SHAMIR_CIPHER_HPP