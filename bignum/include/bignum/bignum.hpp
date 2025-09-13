#pragma once

#include <string>
#include <memory>
#include <utility>
#include <cstdint>

namespace bignum {

class BigInt {
public:
    // --- Конструкторы и присваивание ---
    // Может принимать десятичные ("123") и шестнадцатеричные ("0xabc") строки.
    explicit BigInt(const std::string& number_str = "0");
    BigInt(int64_t val); // Для удобства работы со встроенными знаковыми типами.
    BigInt(const BigInt& other);
    BigInt& operator=(const BigInt& other);
    BigInt(BigInt&& other) noexcept;
    BigInt& operator=(BigInt&& other) noexcept;
    ~BigInt() = default;

    // --- Унарные операторы ---
    BigInt operator-() const; // Унарный минус (для -a)

    // --- Арифметические операторы ---
    BigInt operator+(const BigInt& other) const;
    BigInt& operator+=(const BigInt& other);
    BigInt operator-(const BigInt& other) const;
    BigInt& operator-=(const BigInt& other);
    BigInt operator*(const BigInt& other) const;
    BigInt& operator*=(const BigInt& other);
    BigInt operator/(const BigInt& other) const;
    BigInt& operator/=(const BigInt& other);
    BigInt operator%(const BigInt& other) const;
    BigInt& operator%=(const BigInt& other);

    // --- Побитовые операторы (работают с модулем числа, знак сохраняется) ---
    BigInt operator<<(size_t bits) const;
    BigInt& operator<<=(size_t bits);
    BigInt operator>>(size_t bits) const;
    BigInt& operator>>=(size_t bits);
    BigInt operator&(const BigInt& other) const;
    BigInt& operator&=(const BigInt& other);
    BigInt operator|(const BigInt& other) const;
    BigInt& operator|=(const BigInt& other);
    BigInt operator^(const BigInt& other) const;
    BigInt& operator^=(const BigInt& other);

    // --- Операторы сравнения ---
    bool operator==(const BigInt& other) const;
    bool operator!=(const BigInt& other) const;
    bool operator<(const BigInt& other) const;
    bool operator>(const BigInt& other) const;
    bool operator<=(const BigInt& other) const;
    bool operator>=(const BigInt& other) const;

    // --- Утилиты ---
    std::string to_hex_string() const;
    std::string to_dec_string() const;
    bool is_zero() const;
    bool is_negative() const;
    size_t bit_length() const;
    BigInt abs() const;

private:
    std::unique_ptr<uint64_t[]> limbs_{nullptr};
    size_t size_{0};
    size_t capacity_{0};
    bool is_negative_{false};

    // --- Приватные методы парсинга ---
    void from_hex_string(const std::string& hex_str);
    void from_dec_string(const std::string& dec_str);

    // --- Приватные "беззнаковые" версии для арифметики над модулями ---
    static BigInt add_magnitude(const BigInt& a, const BigInt& b);
    static BigInt subtract_magnitude(const BigInt& a, const BigInt& b);
    int compare_magnitude(const BigInt& other) const; // -1, 0, 1
    static std::pair<BigInt, BigInt> div_mod_magnitude(const BigInt& dividend, const BigInt& divisor);

    // --- Приватные методы управления ---
    explicit BigInt(size_t num_limbs, bool zero_initialize);
    void resize(size_t new_capacity);
    void strip_leading_zeros();
};

} // namespace bignum