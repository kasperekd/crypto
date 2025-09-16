#include "discrete_log.hpp"
#include "crypto_lib.hpp"
#include <iostream>
#include <string>
#include <stdexcept>

int tests_passed = 0;
int tests_failed = 0;

void ASSERT_EQUAL(const bignum::BigInt& actual, long long expected, const std::string& test_name) {
    bignum::BigInt exp(expected);
    if (!(actual == exp)) {
        std::string error_message = "Assertion failed in " + test_name +
                                  ": Expected " + exp.to_dec_string() +
                                  ", but got " + actual.to_dec_string();
        throw std::runtime_error(error_message);
    }
}

void ASSERT_HAS_VALUE_AND_EQUAL(const std::optional<bignum::BigInt>& actual, long long expected, const std::string& test_name) {
    if (!actual.has_value()) {
        throw std::runtime_error("Assertion failed in " + test_name + ": expected value but got none");
    }
    ASSERT_EQUAL(*actual, expected, test_name);
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

using bignum::BigInt;

void test_discrete_log_small() {
    BigInt p("101");
    BigInt a("2");
    int x_known = 13;
    BigInt y = BigInt(1);
    for (int i = 0; i < x_known; ++i) y = (y * a) % p;
    auto res = discrete_log_bsgs(a, y, p, false);
    ASSERT_HAS_VALUE_AND_EQUAL(res, x_known, "discrete small");
}

void test_discrete_log_generated() {
    BigInt p("1009");
    BigInt a("5");
    int x_known = 123;
    BigInt y = BigInt(1);
    for (int i = 0; i < x_known; ++i) y = (y * a) % p;
    auto res = discrete_log_bsgs(a, y, p, false);
    ASSERT_HAS_VALUE_AND_EQUAL(res, x_known, "discrete generated");
}

int main() {
    std::cout << "Running discrete_log tests..." << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    RUN_TEST(test_discrete_log_small, "TestDiscreteSmall");
    RUN_TEST(test_discrete_log_generated, "TestDiscreteGenerated");

    std::cout << "----------------------------------------" << std::endl;
    std::cout << "Test summary:" << std::endl;
    std::cout << "PASSED: " << tests_passed << std::endl;
    std::cout << "FAILED: " << tests_failed << std::endl;

    return (tests_failed == 0) ? 0 : 1;
}
