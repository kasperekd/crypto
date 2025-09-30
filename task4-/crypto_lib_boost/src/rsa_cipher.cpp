#include "crypto_lib_boost/rsa_cipher.hpp"
#include "crypto_lib_boost/prime_utils.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include <sstream>
#include <fstream>
#include <stdexcept>

namespace rsa_cipher {

RSAKeys generate_keys(int bit_length) {
    RSAKeys keys;
    keys.p = prime_utils::generate_prime(bit_length);
    keys.q = prime_utils::generate_prime(bit_length);
    keys.n = keys.p * keys.q;
    BigInt phi = (keys.p - 1) * (keys.q - 1);
    // choose small e = 65537 if coprime with phi, otherwise generate coprime
    BigInt e_candidate = BigInt(65537);
    if (bignum::gcd(e_candidate, phi) == 1) keys.e = e_candidate;
    else keys.e = prime_utils::generate_coprime(phi);
    keys.d = prime_utils::modular_inverse(keys.e, phi);
    return keys;
}

std::string encrypt(const std::vector<unsigned char>& data, const BigInt& n, const BigInt& e) {
    std::ostringstream os;
    for (unsigned char c : data) {
        BigInt m((int)c);
        BigInt ct = bignum::mod_exp(m, e, n);
        os << ct.str() << " ";
    }
    return os.str();
}

std::vector<unsigned char> decrypt(const std::string& encrypted_data, const BigInt& n, const BigInt& d) {
    std::vector<unsigned char> out;
    std::istringstream is(encrypted_data);
    std::string token;
    while (is >> token) {
        BigInt ct(token);
        BigInt m = bignum::mod_exp(ct, d, n);
        unsigned long mv = m.convert_to<unsigned long>();
        out.push_back((unsigned char)mv);
    }
    return out;
}

void save_keys_to_files(const RSAKeys& keys, const std::string& base_filename) {
    std::string n_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.n.str())));
    std::string e_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.e.str())));
    std::string d_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.d.str())));
    std::string p_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.p.str())));
    std::string q_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.q.str())));

    std::ofstream pub_file(base_filename + ".pub");
    if (!pub_file.is_open()) throw std::runtime_error("Cannot create public key file.");
    pub_file << "n:" << n_b64 << "\n";
    pub_file << "e:" << e_b64 << "\n";
    pub_file.close();

    std::ofstream priv_file(base_filename + ".key");
    if (!priv_file.is_open()) throw std::runtime_error("Cannot create private key file.");
    priv_file << "p:" << p_b64 << "\n";
    priv_file << "q:" << q_b64 << "\n";
    priv_file << "d:" << d_b64 << "\n";
    priv_file.close();
}

RSAKeys load_public_keys(const std::filesystem::path& pub_key_path) {
    std::ifstream key_file(pub_key_path);
    if (!key_file.is_open()) throw std::runtime_error("Cannot open key file: " + pub_key_path.string());
    RSAKeys keys;
    std::string line;
    while (std::getline(key_file, line)) {
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string k = line.substr(0, pos);
        std::string v = line.substr(pos+1);
        BigInt val(file_handler::bytes_to_str(file_handler::from_base64(v)));
        if (k == "n") keys.n = val;
        else if (k == "e") keys.e = val;
    }
    return keys;
}

RSAKeys load_private_keys(const std::filesystem::path& priv_key_path) {
    std::ifstream key_file(priv_key_path);
    if (!key_file.is_open()) throw std::runtime_error("Cannot open key file: " + priv_key_path.string());
    RSAKeys keys;
    std::string line;
    while (std::getline(key_file, line)) {
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string k = line.substr(0, pos);
        std::string v = line.substr(pos+1);
        BigInt val(file_handler::bytes_to_str(file_handler::from_base64(v)));
        if (k == "p") keys.p = val;
        else if (k == "q") keys.q = val;
        else if (k == "d") keys.d = val;
    }
    keys.n = keys.p * keys.q;
    return keys;
}

} // namespace rsa_cipher
