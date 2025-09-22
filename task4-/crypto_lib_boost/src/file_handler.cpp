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

} // namespace file_handler