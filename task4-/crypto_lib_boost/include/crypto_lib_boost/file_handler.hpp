#ifndef FILE_HANDLER_HPP
#define FILE_HANDLER_HPP

#include <string>
#include <vector>

namespace file_handler {

// Читает файл как бинарный поток байт
std::vector<unsigned char> read_binary_file(const std::string& file_path);

// Записывает бинарный поток байт в файл
void write_binary_file(const std::string& file_path, const std::vector<unsigned char>& data);

// Читает текстовый файл в одну строку (удобно для зашифрованных данных)
std::string read_text_file(const std::string& file_path);

// Записывает строку в текстовый файл
void write_text_file(const std::string& file_path, const std::string& data);

std::vector<unsigned char> to_base64(const std::vector<unsigned char>& data);
std::vector<unsigned char> from_base64(const std::string& base64_str);

std::vector<unsigned char> str_to_bytes(const std::string& str);
std::string bytes_to_str(const std::vector<unsigned char>& bytes);

} // namespace file_handler

#endif // FILE_HANDLER_HPP