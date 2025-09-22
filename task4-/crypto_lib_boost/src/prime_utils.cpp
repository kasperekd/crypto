#include "crypto_lib_boost/prime_utils.hpp"
#include <boost/random.hpp>
#include <boost/integer/common_factor_rt.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/integer/mod_inverse.hpp>
#include <chrono>

namespace prime_utils {

// Инициализируем генератор случайных чисел один раз
boost::random::mt19937 rng(static_cast<unsigned int>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));

BigInt generate_prime(int bit_length) {
    if (bit_length < 2) {
        throw std::invalid_argument("Bit length must be at least 2.");
    }

    BigInt n;
    
    // 1. Определяем нижнюю и верхнюю границы.
    BigInt lower_bound = BigInt(1) << (bit_length - 1);
    BigInt upper_bound = (BigInt(1) << bit_length) - 1;

    // 2. Создаем распределение для генерации чисел в этом диапазоне.
    boost::random::uniform_int_distribution<BigInt> dist(lower_bound, upper_bound);
    
    while (true) {
        // 3. Генерируем случайное число.
        n = dist(rng);
        
        // 4. Убедимся, что число нечетное (это значительно ускоряет поиск).
        if (n % 2 == 0) {
            n++;
        }
        
        // 5. Проверяем, простое ли оно, с помощью теста Миллера-Рабина.
        // 25 раундов - стандарт для криптографической надежности.
        if (boost::multiprecision::miller_rabin_test(n, 25)) {
            return n;
        }
    }
}

BigInt generate_coprime(const BigInt& n) {
    // Эта функция была корректной и остается без изменений.
    boost::random::uniform_int_distribution<BigInt> dist(2, n - 1);
    BigInt coprime;
    while (true) {
        coprime = dist(rng);
        if (boost::integer::gcd(coprime, n) == 1) {
            return coprime;
        }
    }
}

BigInt modular_inverse(const BigInt& a, const BigInt& m) {
    return boost::integer::mod_inverse(a, m);
}

} // namespace prime_utils