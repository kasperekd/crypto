#ifndef VERNAM_CIPHER_HPP
#define VERNAM_CIPHER_HPP

#include "crypto_lib_boost/bignum.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include <vector>
#include <string>

namespace vernam_cipher {

struct VernamKeys {
    BigInt p;
    BigInt g;
    BigInt xa; // private
    BigInt xb; // other private (for tests)
    BigInt pa; // public
    BigInt pb; // public
    BigInt shared; // shared secret
};

VernamKeys generate_keys(size_t p_bits = 32);

void save_keys_to_files(const VernamKeys& keys, const std::string& basename);
VernamKeys load_public_keys(const std::string& pubpath);
VernamKeys load_private_keys(const std::string& keypath);

std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data, const BigInt& p, const BigInt& g, const BigInt& xa, const BigInt& pb);
std::vector<unsigned char> decrypt(const std::vector<unsigned char>& data, const BigInt& p, const BigInt& g, const BigInt& xb, const BigInt& pa);

} // namespace vernam_cipher

#endif // VERNAM_CIPHER_HPP

