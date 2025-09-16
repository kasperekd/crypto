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
    } else {
        uint64_t p_u = 10007;
        uint64_t a_u = 5;
        uint64_t x_u = 1234;
        uint64_t y_u = 1;
        for (uint64_t i = 0; i < x_u; ++i) y_u = ( (__uint128_t)y_u * a_u) % p_u;
        a = BigInt((int64_t)a_u); y = BigInt((int64_t)y_u); p = BigInt((int64_t)p_u);
        std::cout << "Сгенерированный пример: a=" << a.to_dec_string() << " p=" << p.to_dec_string() << " y=" << y.to_dec_string() << " (x известен = 1234)\n";
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
