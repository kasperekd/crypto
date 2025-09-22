#include "crypto_lib_boost/shamir_cipher.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include <iostream>
#include <vector>
#include <cassert>
#include <stdexcept>

int main() {
    try {
        std::cout << "Shamir cipher test (Boost backend)..." << std::endl;

        // 1. Генерация ключей
        shamir_cipher::ShamirKeys keys = shamir_cipher::generate_keys(256); // 256 бит для теста

        // 2. Исходные данные
        std::vector<unsigned char> original_data = {'S', 'h', 'a', 'm', 'i', 'r', ' ', 'w', 'i', 't', 'h', ' ', 'B', 'o', 'o', 's', 't', '!'};

        std::vector<unsigned char> original_data_base64 = file_handler::to_base64(original_data);

        // 3. Шифрование
        auto encrypted_temp = shamir_cipher::encrypt(original_data_base64, keys.p, keys.c_a, keys.c_b);
        auto encrypted_bytes = file_handler::str_to_bytes(encrypted_temp);
        auto encrypted_base64_bytes = file_handler::to_base64(encrypted_bytes);
        std::string encrypted = file_handler::bytes_to_str(encrypted_base64_bytes);

        // 4. Расшифрование
        auto decoded_bytes = file_handler::from_base64(encrypted);
        auto decoded_str = file_handler::bytes_to_str(decoded_bytes);
        std::vector<unsigned char> decrypted = shamir_cipher::decrypt(decoded_str, keys.p, keys.d_a, keys.d_b);

        // 5. Проверка
        assert(original_data_base64 == decrypted);

        std::cout << "Original Data: " << file_handler::bytes_to_str(original_data) << std::endl;
        std::cout << "\nOriginal Data (Base64): " << file_handler::bytes_to_str(original_data_base64) << std::endl;
        std::cout << "\nEncrypted Data: " << encrypted << std::endl;
        std::cout << "Decrypted Data (Base64): " << file_handler::bytes_to_str(decrypted) << std::endl;
        std::cout << "\nDecrypted Data : " << file_handler::bytes_to_str(file_handler::from_base64(file_handler::bytes_to_str(decrypted))) << std::endl;
        std::cout << std::endl;

        std::cout << "----------------------------------------\n";
        std::cout << "Keys:\n";
        std::cout << "p = " <<  file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.p.str()))) << "\n";
        std::cout << "c_a = " <<  file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.c_a.str()))) << "\n";
        std::cout << "d_a = " <<  file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.d_a.str()))) << "\n";
        std::cout << "c_b = " <<  file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.c_b.str()))) << "\n";
        std::cout << "d_b = " <<  file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.d_b.str()))) << "\n";

        std::cout << "[SUCCESS] Test passed!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[FAILURE] Test failed: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}