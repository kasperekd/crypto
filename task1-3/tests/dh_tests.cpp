#include "crypto_lib/diffie_hellman.hpp"
#include "crypto_lib.hpp"
#include <iostream>
#include <stdexcept>

int dh_passed = 0;
int dh_failed = 0;

void ASSERT_TRUE(bool cond, const std::string& name) {
    if (!cond) throw std::runtime_error("Assertion failed: " + name);
}

void test_dh_fixed() {
    using bignum::BigInt;
    // small example: p = 23, g = 5
    BigInt p(23), g(5), XA(6), XB(15);
    BigInt PA = power_mod(g, XA, p);
    BigInt PB = power_mod(g, XB, p);
    BigInt s1 = power_mod(PA, XB, p);
    BigInt s2 = power_mod(PB, XA, p);
    BigInt s3 = dh_shared_from_private(p, g, XA, XB);
    ASSERT_TRUE(s1 == s2, "s1==s2");
    ASSERT_TRUE(s2 == s3, "s2==s3");
}

void test_dh_generate_small() {
    auto params = dh_generate(16); // small prime generation
    // verify public keys and shared secret
    BigInt PA = power_mod(params.g, params.XA, params.p);
    BigInt PB = power_mod(params.g, params.XB, params.p);
    BigInt sA = power_mod(PB, params.XA, params.p);
    BigInt sB = power_mod(PA, params.XB, params.p);
    ASSERT_TRUE(PA == params.PA, "PA matches");
    ASSERT_TRUE(PB == params.PB, "PB matches");
    ASSERT_TRUE(sA == sB, "sA==sB");
    ASSERT_TRUE(sA == params.shared, "sA==shared");
}

void test_dh_generate_large() {
    auto params = dh_generate(128);
    BigInt PA = power_mod(params.g, params.XA, params.p);
    BigInt PB = power_mod(params.g, params.XB, params.p);
    BigInt sA = power_mod(PB, params.XA, params.p);
    BigInt sB = power_mod(PA, params.XB, params.p);
    ASSERT_TRUE(PA == params.PA, "PA matches");
    ASSERT_TRUE(PB == params.PB, "PB matches");
    ASSERT_TRUE(sA == sB, "sA==sB");
    ASSERT_TRUE(sA == params.shared, "sA==shared");
    std::cout << "Generated large DH params:\n";
    std::cout << "p=" << params.p.to_hex_string() << "\n";
    std::cout << "g=" << params.g.to_hex_string() << "\n";
    std::cout << "XA=" << params.XA.to_hex_string() << "\n";
    std::cout << "XB=" << params.XB.to_hex_string() << "\n";
    std::cout << "PA=" << params.PA.to_hex_string() << "\n";
    std::cout << "PB=" << params.PB.to_hex_string() << "\n";
    std::cout << "shared=" << params.shared.to_hex_string() << "\n";
}

int main() {
    std::cout << "Running DH tests..." << std::endl;
    try { test_dh_fixed(); std::cout << "test_dh_fixed OK\n"; dh_passed++; } catch (...) { std::cerr << "test_dh_fixed FAIL\n"; dh_failed++; }
    try { test_dh_generate_small(); std::cout << "test_dh_generate_small OK\n"; dh_passed++; } catch (const std::exception& e) { std::cerr << "test_dh_generate_small FAIL: " << e.what() << "\n"; dh_failed++; }
    try { test_dh_generate_large(); std::cout << "test_dh_generate_large OK\n"; dh_passed++; } catch (const std::exception& e) { std::cerr << "test_dh_generate_large FAIL: " << e.what() << "\n"; dh_failed++; }
    std::cout << "DH tests done. passed=" << dh_passed << " failed=" << dh_failed << std::endl;
    return (dh_failed == 0) ? 0 : 1;
}
