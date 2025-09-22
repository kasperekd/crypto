#include "crypto_lib_boost/shamir_cipher.hpp"
#include "crypto_lib_boost/prime_utils.hpp"
#include <stdexcept>
#include <sstream>

namespace shamir_cipher {

ShamirKeys generate_keys(int bit_length) {
    ShamirKeys keys;
    keys.p = prime_utils::generate_prime(bit_length);
    BigInt phi = keys.p - 1;

    keys.c_a = prime_utils::generate_coprime(phi);
    keys.d_a = prime_utils::modular_inverse(keys.c_a, phi);

    keys.c_b = prime_utils::generate_coprime(phi);
    keys.d_b = prime_utils::modular_inverse(keys.c_b, phi);

    return keys;
}

std::string encrypt(const std::vector<unsigned char>& data, const BigInt& p, const BigInt& c_a, const BigInt& c_b) {
    std::stringstream encrypted_stream;
    for (unsigned char byte : data) {
        BigInt m(byte);
        if (m >= p) {
            throw std::runtime_error("Message byte is larger than p. Use larger keys.");
        }
        BigInt x1 = powm(m, c_a, p);
        BigInt x2 = powm(x1, c_b, p);
        encrypted_stream << x2.str() << " ";
    }
    return encrypted_stream.str();
}

std::vector<unsigned char> decrypt(const std::string& encrypted_data, const BigInt& p, const BigInt& d_a, const BigInt& d_b) {
    std::vector<unsigned char> decrypted_data;
    std::stringstream encrypted_stream(encrypted_data);
    std::string num_str;

    while (encrypted_stream >> num_str) {
        BigInt x2(num_str);
        BigInt x3 = powm(x2, d_a, p);
        BigInt m = powm(x3, d_b, p);
        decrypted_data.push_back(m.convert_to<unsigned char>());
    }
    return decrypted_data;
}

} // namespace shamir_cipher