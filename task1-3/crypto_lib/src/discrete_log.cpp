#include "discrete_log.hpp"
#include "crypto_lib.hpp"
#include <unordered_map>
#include <random>
#include <chrono>
#include <iostream>

using bignum::BigInt;

inline static bool bigint_to_u64_safe(const BigInt& a, uint64_t& out) {
    if (a.is_negative()) return false;
    if (a.bit_length() > 64) return false;
    try {
        out = std::stoull(a.to_dec_string());
        return true;
    } catch (...) {
        return false;
    }
}

std::optional<BigInt> discrete_log_bsgs(const BigInt& a, const BigInt& y, const BigInt& p, bool debug) {
    uint64_t p_u64;
    if (bigint_to_u64_safe(p, p_u64) && p_u64 != 0) {
        uint64_t m = (uint64_t)std::ceil(std::sqrt((long double)p_u64));

        uint64_t a_u64, y_u64;
        if (!bigint_to_u64_safe(a, a_u64) || !bigint_to_u64_safe(y, y_u64)) {
            return std::nullopt;
        }

        // Baby steps: a^{j} * y mod p
        std::unordered_map<uint64_t, uint64_t> table;
        uint64_t aj = 1 % p_u64;
        for (uint64_t j = 0; j < m; ++j) {
            uint64_t val = ( (__uint128_t)aj * y_u64) % p_u64;
            table[val] = j;
            if (debug) std::cout << "baby j=" << j << " val=" << val << std::endl;
            aj = ( (__uint128_t)aj * a_u64) % p_u64;
        }

        // a^{m} mod p
        uint64_t am = 1 % p_u64;
        for (uint64_t i = 0; i < m; ++i) am = ( (__uint128_t)am * a_u64) % p_u64;

        uint64_t gamma = 1 % p_u64;
        for (uint64_t i = 0; i <= m; ++i) {
            if (debug) std::cout << "giant i=" << i << " gamma=" << gamma << std::endl;
            auto it = table.find(gamma);
            if (it != table.end()) {
                uint64_t j = it->second;
                uint64_t x = i * m - j;
                if (debug) std::cout << "match i=" << i << " j=" << j << " x=" << x << std::endl;
                return BigInt((int64_t)x);
            }
            gamma = ( (__uint128_t)gamma * am) % p_u64;
        }

        return std::nullopt;
    }


    const uint64_t MAX_M = 10'000'000ULL;

    size_t bits = p.bit_length();
    
    if (bits > 64*4) {
        return std::nullopt;
    }

    uint64_t m_approx = 0;
    if (bits / 2 < 64) m_approx = (1ULL << ((bits + 1) / 2));
    else return std::nullopt;
    if (m_approx == 0 || m_approx > MAX_M) {

        std::string pdec = p.to_dec_string();
        size_t dlen = pdec.size();

        uint64_t m_from_dec = 1;
        if (dlen / 2 >= 19) return std::nullopt;
        for (size_t i = 0; i < dlen/2; ++i) m_from_dec *= 10ULL;
        if (m_from_dec == 0 || m_from_dec > MAX_M) return std::nullopt;
        m_approx = m_from_dec;
    }

    uint64_t m = m_approx;

    if (debug) std::cout << "Using BigInt BSGS: m=" << m << " (cap " << MAX_M << ")" << std::endl;

    // Baby steps
    std::unordered_map<std::string, uint64_t> table;
    BigInt aj = BigInt(1);
    for (uint64_t j = 0; j < m; ++j) {
        BigInt val = (aj * y) % p;
        std::string key = val.to_dec_string();
        table.emplace(key, j);
        if (debug) std::cout << "baby j=" << j << " val=" << key << std::endl;
        aj = (aj * a) % p;
    }

    // am = a^m mod p
    BigInt am = power_mod(a, BigInt((int64_t)m), p);
    BigInt gamma = BigInt(1);
    for (uint64_t i = 0; i <= m; ++i) {
        std::string key = gamma.to_dec_string();
        if (debug) std::cout << "giant i=" << i << " gamma=" << key << std::endl;
        auto it = table.find(key);
        if (it != table.end()) {
            uint64_t j = it->second;
            uint64_t x = i * m - j;
            if (debug) std::cout << "match i=" << i << " j=" << j << " x=" << x << std::endl;
            return BigInt((int64_t)x);
        }
        gamma = (gamma * am) % p;
    }

    return std::nullopt;
}
