#include "crypto_lib.hpp"
#include <random>
#include <chrono>
#include <utility>
#include <stdexcept>
#include <string>
#include <cstdlib>
using bignum::BigInt;

static bool bigint_to_u64(const BigInt& a, uint64_t& out) {
    if (a.is_negative()) return false;
    if (a.bit_length() > 64) return false;
    try {
        std::string s = a.to_dec_string();
        out = std::stoull(s);
        return true;
    } catch (...) {
        return false;
    }
}

BigInt multiply_mod(const BigInt& a, const BigInt& b, const BigInt& mod) {
    BigInt res(0);
    BigInt base = a % mod;
    BigInt exp = b;
    BigInt two(2);
    while (!exp.is_zero()) {
        if ((exp % two) == BigInt(1)) res = (res + base) % mod;
        base = (base + base) % mod;
        exp = exp >> 1;
    }
    return res;
}

BigInt power_mod(const BigInt& a, const BigInt& x, const BigInt& p) {
    if (p.is_zero()) throw std::runtime_error("Modulus zero in power_mod");
    BigInt res(1);
    BigInt base = a % p;
    BigInt exp = x;
    BigInt two(2);
    while (!exp.is_zero()) {
        if ((exp % two) == BigInt(1)) res = multiply_mod(res, base, p);
        base = multiply_mod(base, base, p);
        exp = exp >> 1;
    }
    return res;
}

bool is_prime_fermat(const BigInt& n, int iterations) {
    if (n.is_negative() || n.is_zero()) return false;
    if (n == BigInt(2) || n == BigInt(3)) return true;
    if ((n % BigInt(2)) == BigInt(0)) return false;

    uint64_t n_u64;
    bool use_u64 = bigint_to_u64(n, n_u64);

    std::mt19937_64 rng(std::chrono::steady_clock::now().time_since_epoch().count());

    for (int i = 0; i < iterations; ++i) {
        BigInt a;
        if (use_u64) {
            if (n_u64 <= 4) return false;
            std::uniform_int_distribution<uint64_t> distrib(2, n_u64 - 2);
            a = BigInt((int64_t)distrib(rng));
        } else {

            a = BigInt(2 + (i % 10));
        }
        BigInt res = power_mod(a, n - BigInt(1), n);
        if (!(res == BigInt(1))) return false;
    }
    return true;
}

BigInt extended_euclidean(const BigInt& a_in, const BigInt& b_in, BigInt& x, BigInt& y) {
    BigInt a = a_in.abs();
    BigInt b = b_in.abs();
    BigInt x0(1), y0(0);
    BigInt x1(0), y1(1);
    while (!b.is_zero()) {
        BigInt q = a / b;
        BigInt r = a % b;
        BigInt x2 = x0 - q * x1;
        BigInt y2 = y0 - q * y1;
        a = b; b = r;
        x0 = x1; x1 = x2;
        y0 = y1; y1 = y2;
    }
    x = x0;
    y = y0;
    return a; // gcd
}

BigInt generate_random_prime(const BigInt& min_in, const BigInt& max_in) {
    BigInt min = min_in;
    BigInt max = max_in;
    if (min > max) std::swap(min, max);
    uint64_t min_u64, max_u64;
    if (!bigint_to_u64(min, min_u64) || !bigint_to_u64(max, max_u64)) {
        throw std::runtime_error("generate_random_prime supports ranges within uint64_t for now");
    }
    std::mt19937_64 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint64_t> distrib(min_u64, max_u64);
    uint64_t num;
    do {
        num = distrib(rng);
    } while (!is_prime_fermat(BigInt((int64_t)num)));
    return BigInt((int64_t)num);
}
