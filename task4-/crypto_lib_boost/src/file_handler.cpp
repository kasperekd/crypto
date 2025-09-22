#include "crypto_lib_boost/file_handler.hpp"
#include <fstream>
#include <iterator>
#include <sstream>
#include <stdexcept>

namespace file_handler {

std::vector<unsigned char> read_binary_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + file_path);
    }
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void write_binary_file(const std::string& file_path, const std::vector<unsigned char>& data) {
    std::ofstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot write to file: " + file_path);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

std::string read_text_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + file_path);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void write_text_file(const std::string& file_path, const std::string& data) {
    std::ofstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot write to file: " + file_path);
    }
    file << data;
}

std::vector<unsigned char> to_base64(const std::vector<unsigned char>& data) {
    static const char* base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    std::vector<unsigned char> encoded;
    encoded.reserve(((data.size() + 2) / 3) * 4);
    int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    return encoded;
}

std::vector<unsigned char> from_base64(const std::string& base64_str) {
    static const char* base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    
    std::vector<unsigned char> decoded;
    decoded.reserve((base64_str.size() * 3) / 4);
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) {
        T[static_cast<unsigned char>(base64_chars[i])] = i;
    }

    int val = 0, valb = -8;
    for (unsigned char c : base64_str) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

std::vector<unsigned char> str_to_bytes(const std::string& str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}

std::string bytes_to_str(const std::vector<unsigned char>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

} // namespace file_handler