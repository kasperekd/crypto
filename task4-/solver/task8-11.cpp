#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include "crypto_lib_boost/file_handler.hpp"
#include "crypto_lib_boost/signature_interface.hpp"

static void do_keygen(const std::string& algo) {
    int bits;
    std::cout << "\nВведите размер ключа в битах: ";
    std::cin >> bits;
    if (algo == "RSA") {
        auto kp = signature::generate_rsa_keys(bits);
        std::cout << "Сгенерированы ключи: " << kp.priv_path << ", " << kp.pub_path << "\n";
    } else if (algo == "ElGamal") {
        auto kp = signature::generate_elgamal_keys(bits);
        std::cout << "Сгенерированы ключи: " << kp.priv_path << ", " << kp.pub_path << "\n";
    } else if (algo == "GOST") {
        auto kp = signature::generate_gost_keys(bits);
        std::cout << "Сгенерированы ключи: " << kp.priv_path << ", " << kp.pub_path << "\n";
    } else if (algo == "DSA") {
        auto kp = signature::generate_dsa_keys(bits);
        std::cout << "Сгенерированы ключи: " << kp.priv_path << ", " << kp.pub_path << "\n";
    }
}

static void do_sign(const std::string& algo) {
    std::string priv, filepath, out_sig_path;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cout << "\nПуть к приватному ключу (.key): "; std::getline(std::cin, priv);
    std::cout << "Путь к файлу для подписи: "; std::getline(std::cin, filepath);
    // sign
    std::vector<unsigned char> sig;
    if (algo == "RSA") sig = signature::rsa_sign_file(priv, filepath);
    else if (algo == "ElGamal") sig = signature::elgamal_sign_file(priv, filepath);
    else if (algo == "GOST") sig = signature::gost_sign_file(priv, filepath);
    else if (algo == "DSA") sig = signature::dsa_sign_file(priv, filepath);

    std::cout << "Сохранить подпись в файл (путь): "; std::getline(std::cin, out_sig_path);
    if (!out_sig_path.empty()) {
        auto b64 = file_handler::bytes_to_str(file_handler::to_base64(sig));
        file_handler::write_text_file(out_sig_path, b64);
        std::cout << "Подпись сохранена: " << out_sig_path << "\n";
    }
}

static void do_verify(const std::string& algo) {
    std::string pub, filepath, sig_path;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cout << "\nПуть к публичному ключу (.pub): "; std::getline(std::cin, pub);
    std::cout << "Путь к файлу для проверки: "; std::getline(std::cin, filepath);
    std::cout << "Путь к файлу подписи (Base64): "; std::getline(std::cin, sig_path);
    std::string b64 = file_handler::read_text_file(sig_path);
    std::vector<unsigned char> sig = file_handler::from_base64(b64);
    bool ok = false;
    if (algo == "RSA") ok = signature::rsa_verify_file(pub, filepath, sig);
    else if (algo == "ElGamal") ok = signature::elgamal_verify_file(pub, filepath, sig);
    else if (algo == "GOST") ok = signature::gost_verify_file(pub, filepath, sig);
    else if (algo == "DSA") ok = signature::dsa_verify_file(pub, filepath, sig);
    std::cout << (ok ? "Подпись верна\n" : "Подпись НЕ верна\n");
}

void signatures_menu() {
    int choice;
    while (true) {
        std::cout << "\n--- Меню Электронных Подписей ---\n";
        std::cout << "8. RSA подпись\n";
        std::cout << "9. ElGamal подпись\n";
        std::cout << "10. GOST R 34.10-94 подпись\n";
        std::cout << "11. FIPS 186 (DSA) подпись\n";
        std::cout << "0. Назад\n";
        std::cout << "> "; std::cin >> choice;
        if (choice == 0) return;
        std::string algo;
        if (choice == 8) algo = "RSA";
        else if (choice == 9) algo = "ElGamal";
        else if (choice == 10) algo = "GOST";
        else if (choice == 11) algo = "DSA";
        else { std::cout << "Неверный выбор\n"; continue; }

        int op;
        std::cout << "1. Сгенерировать ключи\n2. Подписать файл\n3. Проверить подпись\n0. Назад\n> ";
        std::cin >> op;
        if (op == 0) continue;
        try {
            switch (op) {
                case 1: do_keygen(algo); break;
                case 2: do_sign(algo); break;
                case 3: do_verify(algo); break;
                default: std::cout << "Неверный выбор\n"; break;
            }
        } catch (const std::exception& e) {
            std::cerr << "Ошибка: " << e.what() << "\n";
        }
    }
}

int main(int argc, char** argv) {
    std::cout << "Signature tasks runner (8-11)\n";
    signatures_menu();
    return 0;
}

// end of file
