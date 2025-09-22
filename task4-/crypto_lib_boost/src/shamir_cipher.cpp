#include "crypto_lib_boost/shamir_cipher.hpp"
#include "crypto_lib_boost/prime_utils.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include <stdexcept>
#include <sstream>
#include <map>
#include <fstream>

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

void save_keys_to_files(const ShamirKeys& keys, const std::string& base_filename) {
    std::string p_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.p.str())));
    std::string ca_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.c_a.str())));
    std::string da_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.d_a.str())));
    std::string cb_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.c_b.str())));
    std::string db_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.d_b.str())));

    // --- Сохраняем публичный ключ ---
    std::ofstream pub_file(base_filename + ".pub");
    if (!pub_file.is_open()) throw std::runtime_error("Cannot create public key file.");
    pub_file << "p:" << p_b64 << "\n";
    pub_file << "c_a:" << ca_b64 << "\n";
    pub_file << "c_b:" << cb_b64 << "\n";
    pub_file.close();

    // --- Сохраняем приватный ключ ---
    std::ofstream priv_file(base_filename + ".key");
    if (!priv_file.is_open()) throw std::runtime_error("Cannot create private key file.");
    priv_file << "p:" << p_b64 << "\n";
    priv_file << "d_a:" << da_b64 << "\n";
    priv_file << "d_b:" << db_b64 << "\n";
    priv_file.close();
}

// Вспомогательная функция для парсинга файлов ключей
std::map<std::string, BigInt> parse_key_file(const std::filesystem::path& key_path) {
    std::ifstream key_file(key_path);
    if (!key_file.is_open()) throw std::runtime_error("Cannot open key file: " + key_path.string());

    std::map<std::string, BigInt> key_map;
    std::string line;
    while (std::getline(key_file, line)) {
        std::stringstream ss(line);
        std::string key_name;
        std::string base64_val;
        if (std::getline(ss, key_name, ':') && std::getline(ss, base64_val)) {
            key_map[key_name] = BigInt(file_handler::bytes_to_str(file_handler::from_base64(base64_val)));
        }
    }
    return key_map;
}

ShamirKeys load_public_keys(const std::filesystem::path& pub_key_path) {
    auto key_map = parse_key_file(pub_key_path);
    ShamirKeys keys;
    keys.p = key_map.at("p");
    keys.c_a = key_map.at("c_a");
    keys.c_b = key_map.at("c_b");
    return keys;
}

ShamirKeys load_private_keys(const std::filesystem::path& priv_key_path) {
    auto key_map = parse_key_file(priv_key_path);
    ShamirKeys keys;
    keys.p = key_map.at("p");
    keys.d_a = key_map.at("d_a");
    keys.d_b = key_map.at("d_b");
    return keys;
}

} // namespace shamir_cipher