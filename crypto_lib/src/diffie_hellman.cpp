#include "crypto_lib/diffie_hellman.hpp"
#include "crypto_lib.hpp"
#include <random>
#include <chrono>

using bignum::BigInt;

BigInt dh_shared_from_private(const BigInt& p, const BigInt& g, const BigInt& XA, const BigInt& XB) {
    // compute public keys
    BigInt PA = power_mod(g, XA, p);
    BigInt PB = power_mod(g, XB, p);
    // compute shared secret: PB^{XA} mod p (or PA^{XB})
    BigInt shared = power_mod(PB, XA, p);
    return shared;
}

static uint64_t rng_u64() {
    static std::mt19937_64 rng((uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count());
    return rng();
}

// helper: generate a random BigInt in [2, p-2] using decimal-string based method
static BigInt random_big_in_range(const BigInt& p) {
    // naive approach: if p fits in u64 use that, otherwise sample random decimal string of same length
    uint64_t p_u64 = 0;
    try {
        std::string pdec = p.to_dec_string();
        // build a random number with same decimal length but ensure < p
        std::string s;
        s.reserve(pdec.size());
        for (size_t i = 0; i < pdec.size(); ++i) {
            char c = '0' + (rng_u64() % 10);
            s.push_back(c);
        }
        BigInt candidate(s);
        BigInt two(2);
        BigInt maxv = p - two;
        // reduce candidate mod (p-3) and add 2
        BigInt range = maxv - two + BigInt(1);
        if (range.is_zero()) return two;
        BigInt reduced = candidate % range;
        return reduced + two;
    } catch (...) {
        return BigInt(2);
    }
}

DHParams dh_generate(size_t p_bits) {
    if (p_bits < 16) p_bits = 16;
    // Use the new bits-based prime generator
    BigInt p = generate_random_prime_bits(p_bits);
    // choose g = 2 .. p-2 (naive, not guaranteed to be a generator for multiplicative group)
    BigInt two(2);
    BigInt g = random_big_in_range(p);
    if (g < two) g = two;

    // generate private exponents of roughly p_bits-1 bits
    BigInt XA = generate_random_prime_bits(std::max((size_t)8, p_bits - 1));
    BigInt XB = generate_random_prime_bits(std::max((size_t)8, p_bits - 1));

    BigInt PA = power_mod(g, XA, p);
    BigInt PB = power_mod(g, XB, p);
    BigInt shared = power_mod(PB, XA, p);

    DHParams out{p, g, XA, XB, PA, PB, shared};
    return out;
}
