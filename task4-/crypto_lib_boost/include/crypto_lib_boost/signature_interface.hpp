#ifndef SIGNATURE_INTERFACE_HPP
#define SIGNATURE_INTERFACE_HPP

#include <vector>
#include <string>

namespace signature {

struct KeyPair {
    std::string priv_path;
    std::string pub_path;
};

// Generic operations each signature module should expose
KeyPair generate_rsa_keys(int bits = 2048);
std::vector<unsigned char> rsa_sign_file(const std::string& priv_key_path, const std::string& file_path);
bool rsa_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig);

KeyPair generate_elgamal_keys(int bits = 1024);
std::vector<unsigned char> elgamal_sign_file(const std::string& priv_key_path, const std::string& file_path);
bool elgamal_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig);

KeyPair generate_gost_keys(int bits = 256);
std::vector<unsigned char> gost_sign_file(const std::string& priv_key_path, const std::string& file_path);
bool gost_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig);

KeyPair generate_dsa_keys(int bits = 1024);
std::vector<unsigned char> dsa_sign_file(const std::string& priv_key_path, const std::string& file_path);
bool dsa_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig);

} // namespace signature

#endif // SIGNATURE_INTERFACE_HPP
