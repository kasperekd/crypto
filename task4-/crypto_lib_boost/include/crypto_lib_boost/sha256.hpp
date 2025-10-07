#ifndef SHA256_HPP
#define SHA256_HPP

#include <vector>
#include <string>

namespace crypto_hash {
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data);
std::vector<unsigned char> sha256_of_file(const std::string& path);
std::string sha256_hex(const std::vector<unsigned char>& digest);
}

#endif // SHA256_HPP
