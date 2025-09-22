#include "discrete_log.hpp"
#include "crypto_lib.hpp"
#include <iostream>
#include <random>
#include <chrono>

using bignum::BigInt;

int main_interactive_discrete_log() {
    std::cout << "Дискретный логарифм (baby-step giant-step)\n";
    std::cout << "1) Ввести a,y,p вручную\n";
    std::cout << "2) Сгенерировать случайный небольшой пример\n";
    std::cout << "Выберите опцию: ";
    int choice; std::cin >> choice;

    BigInt a, y, p;
    if (choice == 1) {
        std::string sa, sy, sp;
        std::cout << "Введите a: "; std::cin >> sa;
        std::cout << "Введите y: "; std::cin >> sy;
        std::cout << "Введите p: "; std::cin >> sp;
        a = BigInt(sa); y = BigInt(sy); p = BigInt(sp);
        std::cout << "Введено: a=" << a.to_dec_string() << " p=" << p.to_dec_string() << " y=" << y.to_dec_string() << "\n";
    } else {
        // BigInt p_u("1007");
        // BigInt a_u("5");
        // BigInt x_u("1234");
        // BigInt y_u("1");
        // // uint64_t p_u = 10007;
        // // uint64_t a_u = 5;
        // // uint64_t x_u = 1234;
        // // uint64_t y_u = 1;
        // for (BigInt i = 0; i < x_u; i += 1) y_u = ( y_u * a_u) % p_u;
        // a = a_u; y = y_u; p = p_u;

        uint64_t a_u = 5;
        uint64_t y_u = 3;
        uint64_t p_u = 23;
        uint64_t x_u = 16;
        // for (uint64_t i = 0; i < x_u; ++i) y_u = ( (__uint128_t)y_u * a_u) % p_u;
        a = BigInt((int64_t)a_u); y = BigInt((int64_t)y_u); p = BigInt((int64_t)p_u);
        std::cout << "Сгенерированный пример: a=" << a.to_dec_string() << " p=" << p.to_dec_string() << " y=" << y.to_dec_string() << "\n";
    }

    auto res = discrete_log_bsgs(a, y, p, true);
    if (res) {
        std::cout << "Найдено x = " << res->to_dec_string() << std::endl;
        return 0;
    } else {
        std::cout << "Решение не найдено." << std::endl;
        return 2;
    }
}

int main() { return main_interactive_discrete_log(); }
