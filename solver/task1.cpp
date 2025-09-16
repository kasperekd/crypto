#include "crypto_lib.hpp"
#include <iostream>
#include <random>
#include <chrono>

using bignum::BigInt;

void demo_extended_euclidean() {
    int choice;
    BigInt a, b, x, y;

    std::cout << "Выберите способ получения чисел a и b:\n";
    std::cout << "1. Ввести с клавиатуры\n";
    std::cout << "2. Сгенерировать случайно\n";
    std::cout << "3. Сгенерировать случайно (простые числа)\n";
    std::cout << "Ваш выбор: ";
    std::cin >> choice;

    const long long MAX_VAL = 1'000'000'000LL;

    switch (choice) {
        case 1: {
            std::string sa, sb;
            std::cout << "Введите a: ";
            std::cin >> sa;
            std::cout << "Введите b: ";
            std::cin >> sb;
            a = BigInt(sa);
            b = BigInt(sb);
            break;
        }
        case 2: {
            std::mt19937_64 rng(std::chrono::steady_clock::now().time_since_epoch().count());
            std::uniform_int_distribution<long long> distrib(1, MAX_VAL);
            a = BigInt(distrib(rng));
            b = BigInt(distrib(rng));
            std::cout << "Сгенерированы числа: a = " << a.to_dec_string() << ", b = " << b.to_dec_string() << std::endl;
            break;
        }
        case 3:
            a = generate_random_prime(BigInt(1000), BigInt(MAX_VAL));
            b = generate_random_prime(BigInt(1000), BigInt(MAX_VAL));
            std::cout << "Сгенерированы простые числа: a = " << a.to_dec_string() << ", b = " << b.to_dec_string() << std::endl;
            break;
        default:
            std::cout << "Неверный выбор." << std::endl;
            return;
    }

    BigInt nod = extended_euclidean(a, b, x, y);

    std::cout << "\nРезультаты:\n";
    std::cout << "НОД(" << a.to_dec_string() << ", " << b.to_dec_string() << ") = " << nod.to_dec_string() << std::endl;
    std::cout << "Найдены коэффициенты x и y для уравнения ax + by = НОД(a, b):\n";
    std::cout << "x = " << x.to_dec_string() << ", y = " << y.to_dec_string() << std::endl;
    BigInt check = a * x + b * y;
    std::cout << "Проверка: " << a.to_dec_string() << " * (" << x.to_dec_string() << ") + " << b.to_dec_string() << " * (" << y.to_dec_string() << ") = " << check.to_dec_string() << std::endl;
}

int main() {
    setlocale(LC_ALL, "Russian");
    int choice;
    
    do {
        std::cout << "1. Быстрое возведение в степень по модулю\n";
        std::cout << "2. Тест простоты Ферма\n";
        std::cout << "3. Обобщённый алгоритм Евклида\n";
        std::cout << "0. Выход\n";
        std::cout << "Выберите функцию: ";
        std::cin >> choice;

        switch (choice) {
            case 1: {
                std::string sa, sx, sp;
                std::cout << "Введите основание (a): ";
                std::cin >> sa;
                std::cout << "Введите степень (x): ";
                std::cin >> sx;
                std::cout << "Введите модуль (p): ";
                std::cin >> sp;
                BigInt a(sa), x(sx), p(sp);
                BigInt res = power_mod(a, x, p);
                std::cout << "Результат (" << a.to_dec_string() << "^" << x.to_dec_string() << " mod " << p.to_dec_string() << "): " << res.to_dec_string() << std::endl;
                break;
            }
            case 2: {
                std::string sn;
                std::cout << "Введите число для проверки на простоту: ";
                std::cin >> sn;
                BigInt n(sn);
                if (is_prime_fermat(n)) {
                    std::cout << "Число " << n.to_dec_string() << " вероятно простое." << std::endl;
                } else {
                    std::cout << "Число " << n.to_dec_string() << " является составным." << std::endl;
                }
                break;
            }
            case 3: {
                demo_extended_euclidean();
                break;
            }
            case 0:
                std::cout << "Выход из программы." << std::endl;
                break;
            default:
                std::cout << "Неверный выбор. Попробуйте снова." << std::endl;
        }
    } while (choice != 0);

    return 0;
}
