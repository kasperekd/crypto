#ifndef PRIME_UTILS_HPP
#define PRIME_UTILS_HPP

#include "crypto_lib_boost/bignum.hpp"

namespace prime_utils {

// Генерирует случайное простое число заданной битности
BigInt generate_prime(int bit_length);

// Генерирует число, взаимно простое с заданным
BigInt generate_coprime(const BigInt& n);

// Находит модульное обратное (d * e ≡ 1 (mod m))
BigInt modular_inverse(const BigInt& a, const BigInt& m);

} // namespace prime_utils

#endif // PRIME_UTILS_HPP