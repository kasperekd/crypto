#include "bignum/bignum.hpp"
#include <cassert>
#include <cassert>
#include <iostream>
#include <limits>

#define RUN_TEST(test_name) \
    std::cout << "Running " #test_name "..." << std::endl; \
    test_name(); \
    std::cout << #test_name " PASSED." << std::endl;

void test_edge_cases() {
    using bignum::BigInt;
    // Конструктор по умолчанию
    BigInt d0;
    assert(d0.is_zero());
    assert(!d0.is_negative());
    // Пустая строка
    BigInt d1("");
    assert(d1.is_zero());
    // Строка из всех нулей
    BigInt d2("000000");
    assert(d2.is_zero());
    // Пустой hex
    BigInt d3("0x");
    assert(d3.is_zero());
    // Hex из всех нулей
    BigInt d4("0x0000");
    assert(d4.is_zero());
    // INT64_MIN/MAX
    BigInt minv(std::to_string(std::numeric_limits<int64_t>::min()));
    BigInt maxv(std::to_string(std::numeric_limits<int64_t>::max()));
    assert(minv.to_dec_string() == std::to_string(std::numeric_limits<int64_t>::min()));
    assert(maxv.to_dec_string() == std::to_string(std::numeric_limits<int64_t>::max()));
    // abs/is_negative для -0, 0, отрицательных
    BigInt z("0");
    BigInt mz("-0");
    assert(z.is_zero() && !z.is_negative());
    assert(mz.is_zero() && !mz.is_negative());
    BigInt neg("-123");
    assert(neg.is_negative());
    assert(neg.abs().to_dec_string() == "123");
}

void test_exceptions() {
    using namespace bignum;
    bool caught = false;
    // Некорректный hex
    try { BigInt x("0xG"); } catch (const std::invalid_argument&) { caught = true; }
    assert(caught);
    caught = false;
    // Некорректный dec
    try { BigInt x("12a3"); } catch (const std::invalid_argument&) { caught = true; }
    assert(caught);
    caught = false;
    // Деление на ноль
    try { BigInt("123") / BigInt("0"); } catch (const std::runtime_error&) { caught = true; }
    assert(caught);
    caught = false;
    // Остаток от нуля
    try { BigInt("123") % BigInt("0"); } catch (const std::runtime_error&) { caught = true; }
    assert(caught);
    // (div_mod_magnitude покрывается через / и %)
}

void test_basic_construction() {
    using bignum::BigInt;
    BigInt a("123");
    BigInt b("456");
    BigInt c = a + b;
    assert(c.to_dec_string() == "579");
    assert((BigInt("0") + BigInt("0")).is_zero());
    assert((BigInt("1") + BigInt("0")).to_dec_string() == "1");
}

void test_addition() {
    using bignum::BigInt;
    BigInt a("123");
    BigInt b("456");
    BigInt c = a + b;
    assert(c.to_dec_string() == "579");
    assert((BigInt("0") + BigInt("0")).is_zero());
    assert((BigInt("1") + BigInt("0")).to_dec_string() == "1");
}

void test_subtraction() {
    using bignum::BigInt;
    BigInt a("1000");
    BigInt b("1");
    BigInt c = a - b;
    assert(c.to_dec_string() == "999");
    assert((BigInt("12345678901234567890") - BigInt("12345678901234567889")).to_dec_string() == "1");
    assert((BigInt("100") - BigInt("100")).is_zero());
}

void test_multiplication() {
    using bignum::BigInt;
    BigInt a("123456789");
    BigInt b("987654321");
    BigInt c = a * b;
    assert(c.to_dec_string() == "121932631112635269");
    assert((BigInt("0") * BigInt("12345678901234567890")).is_zero());
}

void test_division() {
    using bignum::BigInt;
    BigInt a("121932631112635269");
    BigInt b("123456789");
    BigInt c = a / b;
    assert(c.to_dec_string() == "987654321");
    BigInt d = a % b;
    assert(d.is_zero());
    assert((BigInt("100") / BigInt("3")).to_dec_string() == "33");
    assert((BigInt("100") % BigInt("3")).to_dec_string() == "1");
}

void test_comparison() {
    using bignum::BigInt;
    BigInt a("1000");
    BigInt b("1001");
    assert(a < b);
    assert(b > a);
    assert(a <= b);
    assert(b >= a);
    assert(a == BigInt("1000"));
    assert(a != b);
}

void test_big_numbers() {
    using bignum::BigInt;
    std::string big1 = "12345678901234567890123456789012345678901234567890";
    std::string big2 = "98765432109876543210987654321098765432109876543210";
    BigInt a(big1);
    BigInt b(big2);
    BigInt sum = a + b;
    assert(sum.to_dec_string() == "111111111011111111101111111110111111111011111111100");
    BigInt diff = b - a;
    assert(diff.to_dec_string() == "86419753208641975320864197532086419753208641975320");
    BigInt prod = BigInt("10000000000000000000000000000000000000000000000000") * BigInt("2");
    assert(prod.to_dec_string() == "20000000000000000000000000000000000000000000000000");
}

void test_negative_numbers() {
    using bignum::BigInt;
    // Конструктор и вывод
    BigInt a("-123");
    BigInt b(-456);
    // Сложение
    BigInt c = a + b; // -123 + -456 = -579
    assert(c.to_dec_string() == "-579");
    // Вычитание
    BigInt d = a - b; // -123 - (-456) = 333
    assert(d.to_dec_string() == "333");
    // Умножение
    BigInt e = a * b; // -123 * -456 = 56088
    assert(e.to_dec_string() == "56088");
    // Деление
    BigInt f = b / a; // -456 / -123 = 3
    assert(f.to_dec_string() == "3");
    BigInt g = b % a; // -456 % -123 = -87
    assert(g.to_dec_string() == "-87");
    // Сравнения
    assert(a < BigInt(0));
    assert(b < a);
    assert(BigInt(-1) < BigInt(0));
    assert(BigInt(-1) < BigInt(1));
    assert(BigInt(-1) == BigInt(-1));
    assert(BigInt(-1) != BigInt(1));
}

void test_negative_mixed_arithmetic() {
    using bignum::BigInt;
    // Сложение
    assert((BigInt("123") + BigInt("-456")).to_dec_string() == "-333");
    assert((BigInt("-123") + BigInt("456")).to_dec_string() == "333");
    assert((BigInt("-123") + BigInt("123")).is_zero());
    // Вычитание
    assert((BigInt("123") - BigInt("-456")).to_dec_string() == "579");
    assert((BigInt("-123") - BigInt("456")).to_dec_string() == "-579");
    assert((BigInt("-123") - BigInt("-456")).to_dec_string() == "333");
    // Умножение
    assert((BigInt("123") * BigInt("-2")).to_dec_string() == "-246");
    assert((BigInt("-123") * BigInt("2")).to_dec_string() == "-246");
    assert((BigInt("-123") * BigInt("-2")).to_dec_string() == "246");
    // Деление
    assert((BigInt("246") / BigInt("-2")).to_dec_string() == "-123");
    assert((BigInt("-246") / BigInt("2")).to_dec_string() == "-123");
    assert((BigInt("-246") / BigInt("-2")).to_dec_string() == "123");
    // Остаток
    assert((BigInt("5") % BigInt("-2")).to_dec_string() == "1");
    assert((BigInt("-5") % BigInt("2")).to_dec_string() == "-1");
    assert((BigInt("-5") % BigInt("-2")).to_dec_string() == "-1");
    // Edge cases
    assert((BigInt("0") - BigInt("0")).is_zero());
    assert((BigInt("0") + BigInt("-0")).is_zero());
    assert((BigInt("-0")).is_zero());
    assert(!BigInt("-0").is_negative());
    // abs, is_negative
    assert(BigInt("-123").abs().to_dec_string() == "123");
    assert(BigInt("-123").is_negative());
    assert(!BigInt("123").is_negative());
}

void test_bitwise_and_utils() {
    using bignum::BigInt;
    // Проверка abs и bit_length
    BigInt a("12345678901234567890");
    assert(a.abs().to_dec_string() == "12345678901234567890");
    assert(a.bit_length() == 64); // python: (12345678901234567890).bit_length() == 64
    BigInt b("-12345678901234567890");
    assert(b.abs().to_dec_string() == "12345678901234567890");
    assert(b.bit_length() == 64);
    // Побитовые операторы (python сверка)
    BigInt x("0xF0F0F0F0F0F0F0F0");
    BigInt y("0x0FF00FF00FF00FF0");
    // &
    auto and_result = (x & y);
    // python: 0xF0F0F0F0F0F0F0F0 & 0x0FF00FF00FF00FF0 = 67555025218437360 = 0xf000f000f000f0
    assert(and_result.to_dec_string() == "67555025218437360");
    assert(and_result.to_hex_string() == "0xf000f000f000f0");
    BigInt neg("-0x1234567890");
    BigInt pos("0x1234567890");
    assert((neg & pos).to_hex_string() == "0x10");
    assert((neg & pos).to_dec_string() == "16");
    assert((neg | pos).to_hex_string() == "-0x10");
    assert((neg ^ pos).to_hex_string() == "-0x20");
    // Проверка inplace-операторов
    BigInt t("0xFF");
    t &= BigInt("0xF0");
    assert(t.to_hex_string() == "0xf0");
    t |= BigInt("0x0F");
    assert(t.to_hex_string() == "0xff");
    t ^= BigInt("0x0F");
    assert(t.to_hex_string() == "0xf0");
    t <<= 4;
    assert(t.to_hex_string() == "0xf00");
    t >>= 8;
    assert(t.to_hex_string() == "0xf");
}

void test_big_negative_numbers() {
    using bignum::BigInt;
    std::string big1 = "-12345678901234567890123456789012345678901234567890";
    std::string big2 = "-98765432109876543210987654321098765432109876543210";
    BigInt a(big1);
    BigInt b(big2);
    // Сложение
    BigInt sum = a + b;
    assert(sum.to_dec_string() == "-111111111011111111101111111110111111111011111111100");
    // Вычитание
    BigInt diff = b - a;
    assert(diff.to_dec_string() == "-86419753208641975320864197532086419753208641975320");
    // Умножение
    BigInt prod = BigInt("-10000000000000000000000000000000000000000000000000") * BigInt("2");
    assert(prod.to_dec_string() == "-20000000000000000000000000000000000000000000000000");
    // Деление
    BigInt div = BigInt("-121932631112635269") / BigInt("-123456789");
    assert(div.to_dec_string() == "987654321");
    // Остаток
    BigInt mod = BigInt("-121932631112635269") % BigInt("-123456789");
    assert(mod.is_zero());
    // Сравнения
    assert(a < BigInt("0"));
    assert(b < a);
    assert(BigInt("-1") < BigInt("0"));
    assert(BigInt("-1") < BigInt("1"));
    assert(BigInt("-1") == BigInt("-1"));
    assert(BigInt("-1") != BigInt("1"));
    // Проверка вывода в hex
}

void test_pow_and_log() {
    using bignum::BigInt;
    // pow(uint64_t)
    assert(BigInt(2).pow(10).to_dec_string() == "1024");
    assert(BigInt(5).pow(0).to_dec_string() == "1");
    assert(BigInt(7).pow(1).to_dec_string() == "7");
    assert(BigInt(10).pow(5).to_dec_string() == "100000");
    // pow(BigInt)
    assert(BigInt(2).pow(BigInt(10)).to_dec_string() == "1024");
    assert(BigInt(3).pow(BigInt(4)).to_dec_string() == "81");
    // большие степени
    BigInt a("123456789");
    BigInt b = a.pow(3);
    assert(b.to_dec_string() == "1881676371789154860897069"); // python: 123456789**3
    // log2
    assert(BigInt(1).log2() == 0);
    assert(BigInt(2).log2() == 1);
    assert(BigInt(3).log2() == 1);
    assert(BigInt(4).log2() == 2);
    assert(BigInt("1024").log2() == 10);
    // log10
    assert(BigInt(1).log10() == 0);
    assert(BigInt(9).log10() == 0);
    assert(BigInt(10).log10() == 1);
    assert(BigInt(99).log10() == 1);
    assert(BigInt(100).log10() == 2);
    assert(BigInt("1000000000000000000000000000000").log10() == 30);
    // Проверка ошибок
    bool caught = false;
    try { BigInt(0).log2(); } catch (const std::domain_error&) { caught = true; }
    assert(caught);
    caught = false;
    try { BigInt(-1).log2(); } catch (const std::domain_error&) { caught = true; }
    assert(caught);
    caught = false;
    try { BigInt(0).log10(); } catch (const std::domain_error&) { caught = true; }
    assert(caught);
    caught = false;
    try { BigInt(-1).log10(); } catch (const std::domain_error&) { caught = true; }
    assert(caught);
}

int main() {
    RUN_TEST(test_basic_construction);
    RUN_TEST(test_addition);
    RUN_TEST(test_subtraction);
    RUN_TEST(test_multiplication);
    RUN_TEST(test_division);
    RUN_TEST(test_comparison);
    RUN_TEST(test_big_numbers);
    RUN_TEST(test_negative_numbers);
    RUN_TEST(test_negative_mixed_arithmetic);
    RUN_TEST(test_big_negative_numbers);
    RUN_TEST(test_bitwise_and_utils);
    RUN_TEST(test_edge_cases);
    RUN_TEST(test_exceptions);
    RUN_TEST(test_pow_and_log);
    return 0;
}