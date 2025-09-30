#include "crypto_lib_boost/elgamal_cipher.hpp"
#include "crypto_lib_boost/prime_utils.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include <sstream>
#include <fstream>
#include <stdexcept>

namespace elgamal_cipher {

ElGamalKeys generate_keys(int bit_length) {
    ElGamalKeys keys;
    keys.p = prime_utils::generate_prime(bit_length);
    // choose small generator g=2 or random in [2,p-2]
    keys.g = BigInt(2);
    BigInt phi = keys.p - 1;
    // choose private exponent d_b in [2, p-2]
    keys.d_b = prime_utils::generate_coprime(phi);
    // compute c_b = g^{d_b} mod p
    keys.c_b = bignum::mod_exp(keys.g, keys.d_b, keys.p);
    return keys;
}

std::string encrypt(const std::vector<unsigned char>& data, const BigInt& p, const BigInt& g, const BigInt& c_b) {
    std::ostringstream os;
    for (unsigned char byte : data) {
        BigInt m((int)byte);
        // choose ephemeral k coprime with p-1
        BigInt k = prime_utils::generate_coprime(p - 1);
        BigInt a = bignum::mod_exp(g, k, p);
        BigInt cbk = bignum::mod_exp(c_b, k, p);
        BigInt b = (m * cbk) % p;
        os << a.str() << ":" << b.str() << " ";
    }
    return os.str();
}

std::vector<unsigned char> decrypt(const std::string& encrypted_data, const BigInt& p, const BigInt& d_b) {
    std::vector<unsigned char> out;
    std::istringstream is(encrypted_data);
    std::string token;
    while (is >> token) {
        auto pos = token.find(':');
        if (pos == std::string::npos) throw std::runtime_error("bad token in elgamal ciphertext");
        std::string a_s = token.substr(0, pos);
        std::string b_s = token.substr(pos+1);
        BigInt a(a_s);
        BigInt b(b_s);
        // m = b * a^{ -d_b } mod p ; compute a^{p-1-d_b} as inverse
        BigInt a_to = bignum::mod_exp(a, p - 1 - d_b, p);
        BigInt m = (b * a_to) % p;
        unsigned long mv = m.convert_to<unsigned long>();
        out.push_back((unsigned char)mv);
    }
    return out;
}

void save_keys_to_files(const ElGamalKeys& keys, const std::string& base_filename) {
    std::string p_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.p.str())));
    std::string g_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.g.str())));
    std::string cb_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.c_b.str())));
    std::string db_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.d_b.str())));

    std::ofstream pub_file(base_filename + ".pub");
    if (!pub_file.is_open()) throw std::runtime_error("Cannot create public key file.");
    pub_file << "p:" << p_b64 << "\n";
    pub_file << "g:" << g_b64 << "\n";
    pub_file << "c_b:" << cb_b64 << "\n";
    pub_file.close();

    std::ofstream priv_file(base_filename + ".key");
    if (!priv_file.is_open()) throw std::runtime_error("Cannot create private key file.");
    priv_file << "p:" << p_b64 << "\n";
    priv_file << "d_b:" << db_b64 << "\n";
    priv_file.close();
}

ElGamalKeys load_public_keys(const std::filesystem::path& pub_key_path) {
    std::ifstream key_file(pub_key_path);
    if (!key_file.is_open()) throw std::runtime_error("Cannot open key file: " + pub_key_path.string());
    ElGamalKeys keys;
    std::string line;
    while (std::getline(key_file, line)) {
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string k = line.substr(0, pos);
        std::string v = line.substr(pos+1);
        BigInt val(file_handler::bytes_to_str(file_handler::from_base64(v)));
        if (k == "p") keys.p = val;
        else if (k == "g") keys.g = val;
        else if (k == "c_b") keys.c_b = val;
    }
    return keys;
}

ElGamalKeys load_private_keys(const std::filesystem::path& priv_key_path) {
    std::ifstream key_file(priv_key_path);
    if (!key_file.is_open()) throw std::runtime_error("Cannot open key file: " + priv_key_path.string());
    ElGamalKeys keys;
    std::string line;
    while (std::getline(key_file, line)) {
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string k = line.substr(0, pos);
        std::string v = line.substr(pos+1);
        BigInt val(file_handler::bytes_to_str(file_handler::from_base64(v)));
        if (k == "p") keys.p = val;
        else if (k == "d_b") keys.d_b = val;
    }
    return keys;
}

} // namespace elgamal_cipher
