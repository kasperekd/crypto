#include "crypto_lib.hpp"
#include <random>
#include <chrono>
#include <sstream>

using bignum::BigInt;

static uint64_t rng_u64_seeded() {
    static std::mt19937_64 rng((uint64_t)std::chrono::steady_clock::now().time_since_epoch().count());
    return rng();
}

static BigInt uniform_random_bits(size_t bits) {
    if (bits == 0) return BigInt(0);
    size_t words = (bits + 63) / 64;
    std::vector<uint64_t> v(words);
    std::mt19937_64 rng((uint64_t)std::chrono::steady_clock::now().time_since_epoch().count());
    for (size_t i = 0; i < words; ++i) v[i] = rng();
    size_t high_bits = bits % 64;
    if (high_bits != 0) {
        uint64_t mask = (high_bits == 64) ? ~0ULL : ((1ULL << high_bits) - 1ULL);
        v.back() &= mask;
    }
    size_t top_index = words - 1;
    size_t top_pos = (bits - 1) % 64;
    v[top_index] |= (1ULL << top_pos);

    // build decimal string by repeatedly adding words * 2^{64*i}
    // naive approach: convert chunks to decimal by multiplying by 2^{64}
    BigInt res(0);
    BigInt two64(1);
    for (size_t i = 0; i < 64; ++i) two64 = two64 + two64; // two64 = 2^64
    BigInt base(1);
    for (size_t i = 0; i < words; ++i) {
        BigInt part((int64_t)0);
        std::string s = std::to_string(v[i]);
        part = BigInt(s);
        res = res + part * base;
        base = base * two64;
    }
    return res;
}

// Miller-Rabin primality test
static bool miller_rabin(const BigInt& n, int iterations) {
    if (n.is_negative() || n.is_zero()) return false;
    if (n == BigInt(2) || n == BigInt(3)) return true;
    if ((n % BigInt(2)) == BigInt(0)) return false;

    BigInt d = n - BigInt(1);
    uint64_t s = 0;
    while ((d % BigInt(2)) == BigInt(0)) {
        d = d / BigInt(2);
        ++s;
    }

    std::mt19937_64 rng((uint64_t)std::chrono::steady_clock::now().time_since_epoch().count());
    for (int i = 0; i < iterations; ++i) {
        // choose a random a in [2, n-2]
        BigInt a = BigInt(2 + (i % 10));
        BigInt x = power_mod(a, d, n);
        if (x == BigInt(1) || x == n - BigInt(1)) continue;
        bool composite = true;
        for (uint64_t r = 1; r < s; ++r) {
            x = multiply_mod(x, x, n);
            if (x == n - BigInt(1)) { composite = false; break; }
        }
        if (composite) return false;
    }
    return true;
}

BigInt generate_random_prime_bits(size_t bits, int mr_iterations) {
    if (bits < 2) throw std::runtime_error("bit size too small");
    for (int attempt = 0; attempt < 100000; ++attempt) {
        BigInt cand = uniform_random_bits(bits);
        // make odd
        if ((cand % BigInt(2)) == BigInt(0)) cand = cand + BigInt(1);
        if (miller_rabin(cand, mr_iterations)) return cand;
    }
    throw std::runtime_error("Failed to generate prime in reasonable attempts");
}
