#include "crypto_lib_boost/sha256.hpp"
#include <openssl/sha.h>
#include <fstream>

namespace crypto_hash {

std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(out.data(), &ctx);
    return out;
}

std::vector<unsigned char> sha256_of_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return sha256(buf);
}

std::string sha256_hex(const std::vector<unsigned char>& digest) {
    static const char* hex = "0123456789abcdef";
    std::string s; s.reserve(digest.size()*2);
    for (unsigned char c : digest) { s.push_back(hex[c>>4]); s.push_back(hex[c&0xF]); }
    return s;
}

} // namespace crypto_hash
