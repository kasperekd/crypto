#include "crypto_lib_boost/signature_interface.hpp"
#include "crypto_lib_boost/elgamal_cipher.hpp"
#include "crypto_lib_boost/sha256.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include "crypto_lib_boost/prime_utils.hpp"
#include "crypto_lib_boost/bignum.hpp"
#include <stdexcept>

namespace signature {

KeyPair generate_elgamal_keys(int bits) {
    auto k = elgamal_cipher::generate_keys(bits);
    elgamal_cipher::save_keys_to_files(k, "elgamal_sig");
    return {"elgamal_sig.key", "elgamal_sig.pub"};
}

std::vector<unsigned char> elgamal_sign_file(const std::string& priv_key_path, const std::string& file_path) {
    // p, g, c_b from public; d_b from private
    auto priv = elgamal_cipher::load_private_keys(priv_key_path);
    std::string pub_path = priv_key_path;
    if (pub_path.size() > 4 && pub_path.substr(pub_path.size()-4) == ".key") {
        pub_path = pub_path.substr(0, pub_path.size()-4) + ".pub";
    } else {
        pub_path = pub_path + ".pub";
    }
    auto pub = elgamal_cipher::load_public_keys(pub_path);

    auto digest = crypto_hash::sha256_of_file(file_path);
    // h = bytes -> BigInt
    BigInt h(0);
    for (unsigned char b : digest) h = h*256 + (int)b;

    BigInt p = pub.p;
    BigInt g = pub.g;
    BigInt x = priv.d_b; // private
    BigInt q = p - 1; // group order
    BigInt m = h % q;

    // choose random k coprime with q
    BigInt k = prime_utils::generate_coprime(q);
    BigInt r = bignum::mod_exp(g, k, p);
    if (r == 0) {
        k = prime_utils::generate_coprime(q);
        r = bignum::mod_exp(g, k, p);
    }
    BigInt k_inv = prime_utils::modular_inverse(k, q);
    BigInt xr = (x * r) % q;
    BigInt s = (k_inv * ((m + q) - (xr % q))) % q; // (m - x*r) mod q

    // signature "r:s"
    std::string out = r.str() + ":" + s.str();
    return file_handler::str_to_bytes(out);
}

bool elgamal_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig) {
    auto keys = elgamal_cipher::load_public_keys(pub_key_path);
    std::string s = file_handler::bytes_to_str(sig);
    auto pos = s.find(':');
    if (pos == std::string::npos) return false;
    BigInt r(s.substr(0, pos));
    BigInt ss(s.substr(pos+1));
    if (r == 0) return false;
    BigInt p = keys.p;
    BigInt q = p - 1;
    if (r >= p) return false;
    auto digest = crypto_hash::sha256_of_file(file_path);
    BigInt h(0);
    for (unsigned char b : digest) h = h*256 + (int)b;
    BigInt m = h % q;
    BigInt v1 = bignum::mod_exp(keys.c_b, r, p);
    BigInt v2 = bignum::mod_exp(r, ss, p);
    BigInt left = (v1 * v2) % p;
    BigInt right = bignum::mod_exp(keys.g, m, p);
    // Canonicality check: signature must exactly match decimal "r:s" bytes
    std::string canonical = r.str() + ":" + ss.str();
    if (file_handler::str_to_bytes(canonical) != sig) return false;
    return left == right;
}

} // namespace signature
