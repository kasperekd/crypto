#include "crypto_lib.hpp"
#include <iostream>
#include <string>
#include <stdexcept>

int tests_passed = 0;
int tests_failed = 0;

// Overload for BigInt vs integer
void ASSERT_EQUAL(const bignum::BigInt& actual, long long expected, const std::string& test_name) {
    bignum::BigInt exp(expected);
    if (!(actual == exp)) {
        std::string error_message = "Assertion failed in " + test_name +
                                  ": Expected " + exp.to_dec_string() +
                                  ", but got " + actual.to_dec_string();
        throw std::runtime_error(error_message);
    }
}

// Overload for bool
void ASSERT_EQUAL(bool actual, bool expected, const std::string& test_name) {
    if (actual != expected) {
        std::string error_message = "Assertion failed in " + test_name +
                                  ": Expected " + (expected ? "true" : "false") +
                                  ", but got " + (actual ? "true" : "false");
        throw std::runtime_error(error_message);
    }
}

void RUN_TEST(void (*test_func)(), const std::string& test_name) {
    std::cout << "[ RUN      ] " << test_name << std::endl;
    try {
        test_func();
        std::cout << "[       OK ] " << test_name << std::endl;
        tests_passed++;
    } catch (const std::runtime_error& e) {
        std::cout << "[  FAILED  ] " << test_name << std::endl;
        std::cerr << "    " << e.what() << std::endl;
        tests_failed++;
    }
}


void test_power_mod() {
    ASSERT_EQUAL(power_mod(bignum::BigInt(2), bignum::BigInt(10), bignum::BigInt(1024)), 0LL, "2^10 mod 1024");
    ASSERT_EQUAL(power_mod(bignum::BigInt(3), bignum::BigInt(5), bignum::BigInt(13)), 9LL, "3^5 mod 13");
    ASSERT_EQUAL(power_mod(bignum::BigInt(123456789), bignum::BigInt(2), bignum::BigInt(987654321)), 478395063LL, "Large numbers power");
    ASSERT_EQUAL(power_mod(bignum::BigInt(987654321), bignum::BigInt(12345), bignum::BigInt(999999937)), 128540957LL, "Large prime modulus");
}

void test_is_prime_fermat() {
    ASSERT_EQUAL(is_prime_fermat(bignum::BigInt(2)), true, "Is prime 2");
    ASSERT_EQUAL(is_prime_fermat(bignum::BigInt(7)), true, "Is prime 7");
    ASSERT_EQUAL(is_prime_fermat(bignum::BigInt(10)), false, "Is prime 10");
    ASSERT_EQUAL(is_prime_fermat(bignum::BigInt(999)), false, "Is prime 999");
    ASSERT_EQUAL(is_prime_fermat(bignum::BigInt(999999937)), true, "Large prime number");
    ASSERT_EQUAL(is_prime_fermat(bignum::BigInt(1000000000)), false, "Large composite number");
}

void test_extended_euclidean() {
    bignum::BigInt x, y;

    bignum::BigInt nod1 = extended_euclidean(bignum::BigInt(48), bignum::BigInt(18), x, y);
    ASSERT_EQUAL(nod1, 6LL, "GCD(48, 18)");
    bignum::BigInt check1 = bignum::BigInt(48) * x + bignum::BigInt(18) * y;
    ASSERT_EQUAL(check1, 6LL, "for 48, 18");

    bignum::BigInt a = bignum::BigInt(987654321);
    bignum::BigInt b = bignum::BigInt(123456789);
    bignum::BigInt nod2 = extended_euclidean(a, b, x, y);
    ASSERT_EQUAL(nod2, 9LL, "GCD for large numbers");
    bignum::BigInt check2 = a * x + b * y;
    ASSERT_EQUAL(check2, 9LL, "for large numbers");
}


int main() {
    std::cout << "Running crypto_lib tests..." << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    RUN_TEST(test_power_mod, "TestPowerMod");
    RUN_TEST(test_is_prime_fermat, "TestIsPrimeFermat");
    RUN_TEST(test_extended_euclidean, "TestExtendedEuclidean");

    std::cout << "----------------------------------------" << std::endl;
    std::cout << "Test summary:" << std::endl;
    std::cout << "PASSED: " << tests_passed << std::endl;
    std::cout << "FAILED: " << tests_failed << std::endl;

    return (tests_failed == 0) ? 0 : 1;
}
