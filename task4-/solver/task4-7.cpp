#include <iostream>
#include <string>
#include <stdexcept>
#include <limits> 
#include <vector> 

#include "crypto_lib_boost/file_handler.hpp"
#include "crypto_lib_boost/shamir_cipher.hpp"
#include "crypto_lib_boost/elgamal_cipher.hpp" 
#include "crypto_lib_boost/rsa_cipher.hpp"  
#include "crypto_lib_boost/vernam_cipher.hpp" 

// --- Vernam handlers ---
void handle_vernam_keygen() {
    std::string basename;
    std::cout << "\nВведите имя для файлов ключей (например, 'my_vernam_key'): ";
    std::cin >> basename;
    std::cout << "\nВведите размер простого модуля p в битах: ";
    int key_size; std::cin >> key_size;
    std::cout << "Генерация " << key_size << "-битного p и ключей..." << std::endl;
    auto keys = vernam_cipher::generate_keys(key_size);
    vernam_cipher::save_keys_to_files(keys, basename);
    std::cout << "Ключи успешно сгенерированы!\n";
    std::cout << "-> Приватный ключ сохранен в: " << basename << ".key\n";
    std::cout << "-> Публичный ключ сохранен в: " << basename << ".pub\n";
}

void handle_vernam_encrypt() {
    std::string input_file, output_file, sender_key_file, receiver_pub_file;
    std::cout << "\nПуть к файлу для шифрования: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, input_file);
    std::cout << "Путь для сохранения зашифрованного файла (text, Base64): "; std::getline(std::cin, output_file);
    std::cout << "Путь к файлу приватного ключа отправителя (.key): "; std::getline(std::cin, sender_key_file);
    std::cout << "Путь к файлу публичного ключа получателя (.pub): "; std::getline(std::cin, receiver_pub_file);

    std::cout << "Загрузка ключей..." << std::endl;
    auto sender_keys = vernam_cipher::load_private_keys(sender_key_file);
    auto receiver_keys = vernam_cipher::load_public_keys(receiver_pub_file);

    std::cout << "Чтение файла..." << std::endl;
    std::vector<unsigned char> data_bytes = file_handler::read_binary_file(input_file);

    std::cout << "Шифрование..." << std::endl;
    auto encrypted_bytes = vernam_cipher::encrypt(data_bytes, sender_keys.p, sender_keys.g, sender_keys.xa, receiver_keys.pb);

    std::string final_base64_output = file_handler::bytes_to_str(file_handler::to_base64(encrypted_bytes));
    file_handler::write_text_file(output_file, final_base64_output);
    std::cout << "Файл успешно зашифрован: " << output_file << std::endl;
}

void handle_vernam_decrypt() {
    std::string input_file, output_file, receiver_key_file, sender_pub_file;
    std::cout << "\nПуть к зашифрованному файлу (text, Base64): ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, input_file);
    std::cout << "Путь для сохранения расшифрованного файла: "; std::getline(std::cin, output_file);
    std::cout << "Путь к файлу приватного ключа получателя (.key): "; std::getline(std::cin, receiver_key_file);
    std::cout << "Путь к файлу публичного ключа отправителя (.pub): "; std::getline(std::cin, sender_pub_file);

    std::cout << "Загрузка ключей..." << std::endl;
    auto receiver_keys = vernam_cipher::load_private_keys(receiver_key_file);
    auto sender_keys = vernam_cipher::load_public_keys(sender_pub_file);

    std::string base64_data_from_file = file_handler::read_text_file(input_file);
    std::vector<unsigned char> raw_encrypted_bytes = file_handler::from_base64(base64_data_from_file);

    std::cout << "Расшифрование..." << std::endl;
    auto decrypted_bytes = vernam_cipher::decrypt(raw_encrypted_bytes, receiver_keys.p, receiver_keys.g, receiver_keys.xa, sender_keys.pb);
    file_handler::write_binary_file(output_file, decrypted_bytes);
    std::cout << "Файл успешно расшифрован: " << output_file << std::endl;
}

void vernam_menu() {
    int choice;
    while (true) {
        std::cout << "\n--- Меню Шифра Вернама ---\n";
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
                case 1: handle_vernam_keygen(); break;
                case 2: handle_vernam_encrypt(); break;
                case 3: handle_vernam_decrypt(); break;
                case 0: return;
                default: std::cout << "Неверный выбор\n"; break;
            }
        } catch (const std::exception& e) {
            std::cerr << "\n!!! ОШИБКА: " << e.what() << " !!!\n";
        }
    }
}

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

// --- ElGamal handlers ---
void handle_elgamal_keygen() {
    std::string basename;
    std::cout << "\nВведите имя для файлов ключей (например, 'my_elgamal_key'): ";
    std::cin >> basename;
    std::cout << "\nВведите размер ключа в битах: ";
    int key_size; std::cin >> key_size;
    std::cout << "Генерация " << key_size << "-битных ключей..." << std::endl;
    auto keys = elgamal_cipher::generate_keys(key_size);
    elgamal_cipher::save_keys_to_files(keys, basename);
    std::cout << "Ключи успешно сгенерированы!\n";
    std::cout << "-> Приватный ключ сохранен в: " << basename << ".key\n";
    std::cout << "-> Публичный ключ сохранен в: " << basename << ".pub\n";
}

void handle_elgamal_encrypt() {
    std::string input_file, output_file, key_file;
    std::cout << "\nПуть к файлу для шифрования: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, input_file);
    std::cout << "Путь для сохранения зашифрованного файла: "; std::getline(std::cin, output_file);
    std::cout << "Путь к файлу публичного ключа (.pub): "; std::getline(std::cin, key_file);
    auto keys = elgamal_cipher::load_public_keys(key_file);
    auto data = file_handler::read_binary_file(input_file);
    std::string enc = elgamal_cipher::encrypt(data, keys.p, keys.g, keys.c_b);
    std::string final_base64_output = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(enc)));
    file_handler::write_text_file(output_file, final_base64_output);
    std::cout << "Файл успешно зашифрован: " << output_file << std::endl;
}

void handle_elgamal_decrypt() {
    std::string input_file, output_file, key_file;
    std::cout << "\nПуть к зашифрованному файлу: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, input_file);
    std::cout << "Путь для сохранения расшифрованного файла: "; std::getline(std::cin, output_file);
    std::cout << "Путь к файлу приватного ключа (.key): "; std::getline(std::cin, key_file);
    auto keys = elgamal_cipher::load_private_keys(key_file);
    std::string base64_data_from_file = file_handler::read_text_file(input_file);
    std::vector<unsigned char> raw_encrypted_bytes = file_handler::from_base64(base64_data_from_file);
    std::string encrypted_str = file_handler::bytes_to_str(raw_encrypted_bytes);
    auto decrypted_data = elgamal_cipher::decrypt(encrypted_str, keys.p, keys.d_b);
    file_handler::write_binary_file(output_file, decrypted_data);
    std::cout << "Файл успешно расшифрован: " << output_file << std::endl;
}

void elgamal_menu() {
    int choice;
    while (true) {
        std::cout << "\n--- Меню Шифра Эль-Гамаля ---\n";
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
                case 1: handle_elgamal_keygen(); break;
                case 2: handle_elgamal_encrypt(); break;
                case 3: handle_elgamal_decrypt(); break;
                case 0: return;
                default: std::cout << "Неверный выбор\n"; break;
            }
        } catch (const std::exception& e) {
            std::cerr << "\n!!! ОШИБКА: " << e.what() << " !!!\n";
        }
    }
}

// --- RSA handlers ---
void handle_rsa_keygen() {
    std::string basename;
    std::cout << "\nВведите имя для файлов ключей (например, 'my_rsa_key'): ";
    std::cin >> basename;
    std::cout << "\nВведите размер ключа в битах (параметр для p и q): ";
    int key_size; std::cin >> key_size;
    std::cout << "Генерация " << key_size << "-битных ключей..." << std::endl;
    auto keys = rsa_cipher::generate_keys(key_size);
    rsa_cipher::save_keys_to_files(keys, basename);
    std::cout << "Ключи успешно сгенерированы!\n";
    std::cout << "-> Приватный ключ сохранен в: " << basename << ".key\n";
    std::cout << "-> Публичный ключ сохранен в: " << basename << ".pub\n";
}

void handle_rsa_encrypt() {
    std::string input_file, output_file, key_file;
    std::cout << "\nПуть к файлу для шифрования: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, input_file);
    std::cout << "Путь для сохранения зашифрованного файла: "; std::getline(std::cin, output_file);
    std::cout << "Путь к файлу публичного ключа (.pub): "; std::getline(std::cin, key_file);
    auto keys = rsa_cipher::load_public_keys(key_file);
    auto data = file_handler::read_binary_file(input_file);
    std::string enc = rsa_cipher::encrypt(data, keys.n, keys.e);
    std::string final_base64_output = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(enc)));
    file_handler::write_text_file(output_file, final_base64_output);
    std::cout << "Файл успешно зашифрован: " << output_file << std::endl;
}

void handle_rsa_decrypt() {
    std::string input_file, output_file, key_file;
    std::cout << "\nПуть к зашифрованному файлу: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, input_file);
    std::cout << "Путь для сохранения расшифрованного файла: "; std::getline(std::cin, output_file);
    std::cout << "Путь к файлу приватного ключа (.key): "; std::getline(std::cin, key_file);
    auto keys = rsa_cipher::load_private_keys(key_file);
    std::string base64_data_from_file = file_handler::read_text_file(input_file);
    std::vector<unsigned char> raw_encrypted_bytes = file_handler::from_base64(base64_data_from_file);
    std::string encrypted_str = file_handler::bytes_to_str(raw_encrypted_bytes);
    auto decrypted_data = rsa_cipher::decrypt(encrypted_str, keys.n, keys.d);
    file_handler::write_binary_file(output_file, decrypted_data);
    std::cout << "Файл успешно расшифрован: " << output_file << std::endl;
}

void rsa_menu() {
    int choice;
    while (true) {
        std::cout << "\n--- Меню Шифра RSA ---\n";
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
                case 1: handle_rsa_keygen(); break;
                case 2: handle_rsa_encrypt(); break;
                case 3: handle_rsa_decrypt(); break;
                case 0: return;
                default: std::cout << "Неверный выбор\n"; break;
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
        std::cout << "5. Шифр Эль-Гамаля\n";
        std::cout << "6. Шифр RSA\n";
        std::cout << "7. Шифр Вернама\n";
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
            case 5: elgamal_menu(); break;
            case 6: rsa_menu(); break;
            case 7: vernam_menu(); break;
            default: std::cout << "Неверный выбор или функция не реализована.\n"; break;
        }
    }
    return 0;
}