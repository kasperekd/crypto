#include "crypto_lib_boost/shamir_cipher.hpp"
#include <iostream>
#include <vector>
#include <cassert>
#include <stdexcept>

int main() {
    try {
        std::cout << "Запуск теста для шифра Шамира (бэкенд Boost)..." << std::endl;

        // 1. Генерация ключей
        shamir_cipher::ShamirKeys keys = shamir_cipher::generate_keys(256); // 256 бит для теста
        std::cout << "Ключи сгенерированы." << std::endl;

        // 2. Исходные данные
        std::vector<unsigned char> original_data = {'S', 'h', 'a', 'm', 'i', 'r', ' ', 'w', 'i', 't', 'h', ' ', 'B', 'o', 'o', 's', 't', '!'};

        // 3. Шифрование
        std::string encrypted = shamir_cipher::encrypt(original_data, keys.p, keys.c_a, keys.c_b);
        std::cout << "Данные зашифрованы." << std::endl;

        // 4. Расшифрование
        std::vector<unsigned char> decrypted = shamir_cipher::decrypt(encrypted, keys.p, keys.d_a, keys.d_b);
        std::cout << "Данные расшифрованы." << std::endl;

        // 5. Проверка
        assert(original_data == decrypted);

        std::cout << "[SUCCESS] Тест шифра Шамира успешно пройден!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[FAILURE] Тест провален: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}