#ifndef CRYPTO_LIB_HPP
#define CRYPTO_LIB_HPP

#include "bignum/bignum.hpp"

using bignum::BigInt;

BigInt multiply_mod(const BigInt& a, const BigInt& b, const BigInt& mod);

BigInt power_mod(const BigInt& a, const BigInt& x, const BigInt& p);

bool is_prime_fermat(const BigInt& n, int iterations = 50);

BigInt extended_euclidean(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y);

BigInt generate_random_prime(const BigInt& min, const BigInt& max);

// Generate a random prime of approximately `bits` bits using Miller-Rabin.
// This is probabilistic; `mr_iterations` controls MR rounds (default 20).
BigInt generate_random_prime_bits(size_t bits, int mr_iterations = 20);

#endif // CRYPTO_LIB_HPP
