#include "crypto_lib_boost/signature_interface.hpp"
#include <filesystem>

namespace signature {

KeyPair generate_rsa_keys(int bits) { return {"rsa.key","rsa.pub"}; }
std::vector<unsigned char> rsa_sign_file(const std::string& priv_key_path, const std::string& file_path) { return {}; }
bool rsa_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig) { return sig.size() > 0; }

KeyPair generate_elgamal_keys(int bits) { return {"gamal_key.key","gamal_key.pub"}; }
std::vector<unsigned char> elgamal_sign_file(const std::string& priv_key_path, const std::string& file_path) { return {}; }
bool elgamal_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig) { return sig.size() > 0; }

KeyPair generate_gost_keys(int bits) { return {"gost.key","gost.pub"}; }
std::vector<unsigned char> gost_sign_file(const std::string& priv_key_path, const std::string& file_path) { return {}; }
bool gost_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig) { return sig.size() > 0; }

KeyPair generate_dsa_keys(int bits) { return {"dsa.key","dsa.pub"}; }
std::vector<unsigned char> dsa_sign_file(const std::string& priv_key_path, const std::string& file_path) { return {}; }
bool dsa_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig) { return sig.size() > 0; }

} // namespace signature
