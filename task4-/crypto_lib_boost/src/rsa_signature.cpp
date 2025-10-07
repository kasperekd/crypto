#include "crypto_lib_boost/signature_interface.hpp"
#include "crypto_lib_boost/sha256.hpp"
#include "crypto_lib_boost/rsa_cipher.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include "crypto_lib_boost/bignum.hpp"
#include <stdexcept>

namespace signature {

KeyPair generate_rsa_keys(int bits) {
    auto k = rsa_cipher::generate_keys(bits/2);
    rsa_cipher::save_keys_to_files(k, "rsa_sig");
    return {"rsa_sig.key", "rsa_sig.pub"};
}

std::vector<unsigned char> rsa_sign_file(const std::string& priv_key_path, const std::string& file_path) {
    auto keys = rsa_cipher::load_private_keys(priv_key_path);
    auto digest = crypto_hash::sha256_of_file(file_path);
    // h = bytes -> BigInt
    std::string hex = crypto_hash::sha256_hex(digest);
    // interpret hex as decimal by converting to BigInt via string of bytes
    BigInt h(0);
    for (unsigned char b : digest) {
        h = h * 256 + (int)b;
    }
    // reduce hash modulo n to ensure it fits into the modulus
    if (keys.n != 0) h = h % keys.n;
    BigInt sig = bignum::mod_exp(h, keys.d, keys.n);
    std::string s = sig.str();
    auto bytes = file_handler::str_to_bytes(s);
    return bytes;
}

bool rsa_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig) {
    auto keys = rsa_cipher::load_public_keys(pub_key_path);
    std::string s = file_handler::bytes_to_str(sig);
    BigInt sig_int(s);
    BigInt m = bignum::mod_exp(sig_int, keys.e, keys.n);
    auto digest = crypto_hash::sha256_of_file(file_path);
    BigInt h(0);
    for (unsigned char b : digest) h = h*256 + (int)b;
    if (keys.n != 0) h = h % keys.n;
    return (m == h);
}

} // namespace signature
