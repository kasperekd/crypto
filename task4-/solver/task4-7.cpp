#include <iostream>
#include <string>
#include <stdexcept>
#include "crypto_lib_boost/file_handler.hpp"
#include "crypto_lib_boost/shamir_cipher.hpp"
// #include "crypto_lib_boost/elgamal_cipher.hpp"   
// #include "crypto_lib_boost/rsa_cipher.hpp"       
// #include "crypto_lib_boost/vernam_cipher.hpp"    

void handle_shamir() {
    int mode_choice;
    std::cout << "\n--- Шифр Шамира ---\n";
    std::cout << "1. Зашифровать файл\n";
    std::cout << "2. Расшифровать файл\n";
    std::cout << "> ";
    std::cin >> mode_choice;

    std::string input_file, output_file;
    std::cout << "Путь к входному файлу: ";
    std::cin >> input_file;
    std::cout << "Путь к выходному файлу: ";
    std::cin >> output_file;

    shamir_cipher::ShamirKeys keys;
    int key_choice;
    std::cout << "1. Сгенерировать ключи автоматически\n";
    std::cout << "2. Ввести ключи вручную\n";
    std::cout << "> ";
    std::cin >> key_choice;

    if (key_choice == 1) {
        std::cout << "Генерация ключей..." << std::endl;
        keys = shamir_cipher::generate_keys();
        std::cout << "Сгенерированные ключи:\n";
        std::cout << "p = " << keys.p.str() << "\n";
        std::cout << "c_a = " << keys.c_a.str() << "\n";
        std::cout << "d_a = " << keys.d_a.str() << "\n";
        std::cout << "c_b = " << keys.c_b.str() << "\n";
        std::cout << "d_b = " << keys.d_b.str() << "\n";
    } else {
        std::string p_str, ca_str, da_str, cb_str, db_str;
        std::cout << "Введите p: "; std::cin >> p_str; keys.p = BigInt(p_str);
        if (mode_choice == 1) { // Для шифрования нужны c_a, c_b
            std::cout << "Введите c_a: "; std::cin >> ca_str; keys.c_a = BigInt(ca_str);
            std::cout << "Введите c_b: "; std::cin >> cb_str; keys.c_b = BigInt(cb_str);
        } else { // Для расшифрования нужны d_a, d_b
            std::cout << "Введите d_a: "; std::cin >> da_str; keys.d_a = BigInt(da_str);
            std::cout << "Введите d_b: "; std::cin >> db_str; keys.d_b = BigInt(db_str);
        }
    }
    
    try {
        if (mode_choice == 1) { // Шифрование
            auto data = file_handler::read_binary_file(input_file);
            std::string encrypted = shamir_cipher::encrypt(data, keys.p, keys.c_a, keys.c_b);
            file_handler::write_text_file(output_file, encrypted);
        } else { // Расшифрование
            std::string encrypted_data = file_handler::read_text_file(input_file);
            auto decrypted = shamir_cipher::decrypt(encrypted_data, keys.p, keys.d_a, keys.d_b);
            file_handler::write_binary_file(output_file, decrypted);
        }
        std::cout << "Операция успешно завершена.\n";
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

void display_menu() {
    std::cout << "\n===== Меню выбора лабораторной работы =====\n";
    std::cout << "4. Шифр Шамира (Лабораторная работа №4)\n";
    std::cout << "5. Шифр Эль-Гамаля (Лабораторная работа №5)\n";
    std::cout << "6. Шифр RSA (Лабораторная работа №6)\n";
    std::cout << "7. Шифр Вернама (Лабораторная работа №7)\n";
    std::cout << "0. Выход\n";
    std::cout << "=========================================\n";
    std::cout << "> ";
}

int main() {
    int choice;
    while (true) {
        display_menu();
        std::cin >> choice;
        if(std::cin.fail() || choice < 0 || choice > 7) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Неверный ввод. Пожалуйста, введите число от 0 до 7.\n";
            continue;
        }

        if (choice == 0) break;

        switch (choice) {
            case 4:
                handle_shamir();
                break;
            case 5:
                std::cout << "Реализация шифра Эль-Гамаля еще не добавлена.\n";
                break;
            case 6:
                std::cout << "Реализация шифра RSA еще не добавлена.\n";
                break;
            case 7:
                std::cout << "Реализация шифра Вернама еще не добавлена.\n";
                break;
            default:
                std::cout << "Неверный выбор.\n";
                break;
        }
    }
    return 0;
}