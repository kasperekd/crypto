#include <iostream>
#include <string>
#include <stdexcept>
#include <limits> 
#include <vector> 

#include "crypto_lib_boost/file_handler.hpp"
#include "crypto_lib_boost/shamir_cipher.hpp"
// #include "crypto_lib_boost/elgamal_cipher.hpp" 
// #include "crypto_lib_boost/rsa_cipher.hpp"  
// #include "crypto_lib_boost/vernam_cipher.hpp" 

void handle_shamir_keygen() {
    std::string basename;
    std::cout << "\nВведите имя для файлов ключей (например, 'my_shamir_key'): ";
    std::cin >> basename;

    std::cout << "\nВведите размер ключа в битах: ";
    int key_size;
    std::cin >> key_size;

    std::cout << "Генерация " << key_size << "-битных ключей..." << std::endl;
    shamir_cipher::ShamirKeys keys = shamir_cipher::generate_keys(key_size);

    shamir_cipher::save_keys_to_files(keys, basename);
    
    std::cout << "Ключи успешно сгенерированы!\n";
    std::cout << "-> Приватный ключ сохранен в: " << basename << ".key\n";
    std::cout << "-> Публичный ключ сохранен в: " << basename << ".pub\n";
}

// --- Обработчик для шифрования файла ---
void handle_shamir_encrypt() {
    std::string input_file, output_file, key_file;
    std::cout << "\nПуть к файлу для шифрования: ";
    // Убедимся, что cin читает всю строку, включая пробелы
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 
    std::getline(std::cin, input_file);
    std::cout << "Путь для сохранения зашифрованного файла: ";
    std::getline(std::cin, output_file);
    std::cout << "Путь к файлу публичного ключа (.pub): ";
    std::getline(std::cin, key_file);
    
    std::cout << "Загрузка ключей..." << std::endl;
    shamir_cipher::ShamirKeys keys = shamir_cipher::load_public_keys(key_file);
    
    std::cout << "Чтение файла..." << std::endl;
    std::vector<unsigned char> data_bytes = file_handler::read_binary_file(input_file);
    
    std::cout << "Шифрование..." << std::endl;
    // encrypted_data_str содержит числа BigInt, разделенные пробелами
    std::string encrypted_data_str = shamir_cipher::encrypt(data_bytes, keys.p, keys.c_a, keys.c_b);
    
    // Кодируем эту строку в Base64 для безопасного хранения в текстовом файле
    std::string final_base64_output = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(encrypted_data_str)));
    file_handler::write_text_file(output_file, final_base64_output);
    
    std::cout << "Файл успешно зашифрован: " << output_file << std::endl;
}

// --- Обработчик для расшифрования файла ---
void handle_shamir_decrypt() {
    std::string input_file, output_file, key_file;
    std::cout << "\nПуть к зашифрованному файлу: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, input_file);
    std::cout << "Путь для сохранения расшифрованного файла: ";
    std::getline(std::cin, output_file);
    std::cout << "Путь к файлу приватного ключа (.key): ";
    std::getline(std::cin, key_file);

    std::cout << "Загрузка ключей..." << std::endl;
    shamir_cipher::ShamirKeys keys = shamir_cipher::load_private_keys(key_file);

    std::cout << "Чтение зашифрованного Base64 файла..." << std::endl;
    std::string base64_data_from_file = file_handler::read_text_file(input_file);
    
    // Декодируем Base64 обратно в строку с числами (BigInt, разделенные пробелами)
    std::vector<unsigned char> raw_encrypted_bytes = file_handler::from_base64(base64_data_from_file);
    std::string encrypted_str = file_handler::bytes_to_str(raw_encrypted_bytes);

    std::cout << "Расшифрование..." << std::endl;
    std::vector<unsigned char> decrypted_data_bytes = shamir_cipher::decrypt(encrypted_str, keys.p, keys.d_a, keys.d_b);

    std::cout << "Сохранение расшифрованного файла..." << std::endl;
    file_handler::write_binary_file(output_file, decrypted_data_bytes);
    
    std::cout << "Файл успешно расшифрован: " << output_file << std::endl;
}

void shamir_menu() {
    int choice;
    while (true) {
        std::cout << "\n--- Меню Шифра Шамира ---\n";
        std::cout << "1. Сгенерировать пару ключей\n";
        std::cout << "2. Зашифровать файл\n";
        std::cout << "3. Расшифровать файл\n";
        std::cout << "0. Назад в главное меню\n";
        std::cout << "> ";
        std::cin >> choice;
        if(std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Неверный ввод. Пожалуйста, введите число.\n";
            continue;
        }

        try {
            switch (choice) {
                case 1: handle_shamir_keygen(); break;
                case 2: handle_shamir_encrypt(); break;
                case 3: handle_shamir_decrypt(); break;
                case 0: return;
                default: std::cout << "Неверный выбор.\n"; break;
            }
        } catch (const std::exception& e) {
            std::cerr << "\n!!! ОШИБКА: " << e.what() << " !!!\n";
        }
    }
}

// --- Главное меню ---
int main() {
    int choice;
    // std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 
    while (true) {
        std::cout << "\n===== Главное Меню =====\n";
        std::cout << "4. Шифр Шамира\n";
        std::cout << "5. Шифр Эль-Гамаля (не реализовано)\n";
        std::cout << "6. Шифр RSA (не реализовано)\n";
        std::cout << "7. Шифр Вернама (не реализовано)\n";
        std::cout << "0. Выход\n";
        std::cout << "> ";
        std::cin >> choice;

        if(std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Неверный ввод. Пожалуйста, введите число от 0 до 7.\n";
            continue;
        }

        if (choice == 0) break;
        switch (choice) {
            case 4: shamir_menu(); break;
            case 5: std::cout << "Реализация шифра Эль-Гамаля еще не добавлена.\n"; break;
            case 6: std::cout << "Реализация шифра RSA еще не добавлена.\n"; break;
            case 7: std::cout << "Реализация шифра Вернама еще не добавлена.\n"; break;
            default: std::cout << "Неверный выбор или функция не реализована.\n"; break;
        }
    }
    return 0;
}