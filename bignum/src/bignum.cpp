#include "bignum/bignum.hpp"
#include <memory>
#include <string>
#include <utility>
#include <complex>
#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <immintrin.h>
#include <vector>


namespace bignum {

BigInt BigInt::pow(uint64_t exp) const {
    // TODO: optimize pow for uint64_t exponent (binary powering, windowing, etc.)
    if (exp == 0) return BigInt(1);
    if (is_zero()) return BigInt(0);
    BigInt result(1);
    for (uint64_t i = 0; i < exp; ++i) {
        result *= *this;
    }
    // Корректируем знак для нечётных exp
    if (is_negative_ && (exp & 1)) result.is_negative_ = true;
    return result;
}

BigInt BigInt::pow(const BigInt& exp) const {
    // TODO: optimize pow for BigInt exponent (binary powering, windowing, etc.)
    if (exp.is_negative()) throw std::invalid_argument("Negative exponent not supported");
    if (exp.is_zero()) return BigInt(1);
    BigInt result(1);
    BigInt i(0);
    while (i < exp) {
        result *= *this;
        i += BigInt(1);
    }
    // Корректируем знак для нечётных exp
    if (is_negative_ && (exp.limbs_[0] & 1)) result.is_negative_ = true;
    return result;
}

size_t BigInt::log2() const {
    if (is_zero() || is_negative_) throw std::domain_error("log2 only for positive numbers");
    return bit_length() - 1;
}

size_t BigInt::log10() const {
    if (is_zero() || is_negative_) throw std::domain_error("log10 only for positive numbers");
    // log10(2) ≈ 0.30103, используем оценку через bit_length
    size_t approx = (size_t)((bit_length() - 1) * 0.30103);
    BigInt ten_pow(1);
    for (size_t i = 0; i < approx; ++i) ten_pow *= 10;
    size_t res = approx;
    BigInt val = this->abs();
    while (val >= ten_pow * 10) {
        ten_pow *= 10;
        ++res;
    }
    while (val < ten_pow) {
        ten_pow /= 10;
        --res;
    }
    return res;
}

uint8_t hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::invalid_argument("Invalid hex character");
} // namespace bignum

uint8_t dec_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    throw std::invalid_argument("Invalid decimal character");
}


BigInt::BigInt(const std::string& number_str_in) {
    if (number_str_in.empty()) {
        return;
    }

    std::string number_str = number_str_in;
    bool negative = false;
    if (number_str[0] == '-') {
        negative = true;
        number_str.erase(0, 1);
    }
    
    if (number_str.rfind("0x", 0) == 0 || number_str.rfind("0X", 0) == 0) {
        from_hex_string(number_str.substr(2));
    } else {
        from_dec_string(number_str);
    }
    if (negative && !is_zero()) {
        is_negative_ = true;
    } else {
        is_negative_ = false;
    }
}

void BigInt::from_hex_string(const std::string& hex_str) {
    if (hex_str.empty() || std::all_of(hex_str.begin(), hex_str.end(), [](char c){ return c == '0'; })) {
        return;
    }
    
    const size_t chars_per_limb = sizeof(uint64_t) * 2;
    const size_t num_limbs = (hex_str.length() + chars_per_limb - 1) / chars_per_limb;

    capacity_ = num_limbs;
    size_ = num_limbs;
    limbs_ = std::make_unique<uint64_t[]>(capacity_);
    std::fill(limbs_.get(), limbs_.get() + capacity_, 0);

    for (size_t i = 0; i < hex_str.length(); ++i) {
        size_t rev_idx = hex_str.length() - 1 - i;
        size_t limb_idx = i / chars_per_limb;
        size_t shift = (i % chars_per_limb) * 4;
        limbs_[limb_idx] |= (uint64_t)hex_char_to_val(hex_str[rev_idx]) << shift;
    }
    strip_leading_zeros();
}

void BigInt::from_dec_string(const std::string& dec_str) {
    if (dec_str.empty() || std::all_of(dec_str.begin(), dec_str.end(), [](char c){ return c == '0'; })) {
        return;
    }

    BigInt ten(10);
    for (char c : dec_str) {
        uint8_t digit = dec_char_to_val(c);
        *this *= ten;
        *this += BigInt(digit);
    }
}

BigInt::BigInt(int64_t val) {
    if (val == 0) return;
    if (val < 0) {
        is_negative_ = true;
        limbs_ = std::make_unique<uint64_t[]>(1);
        limbs_[0] = static_cast<uint64_t>(-(val + 1)) + 1;
    } else {
        is_negative_ = false;
        limbs_ = std::make_unique<uint64_t[]>(1);
        limbs_[0] = static_cast<uint64_t>(val);
    }
    size_ = 1;
    capacity_ = 1;
}

BigInt::BigInt(size_t num_limbs, bool zero_initialize)
    : limbs_(nullptr), size_(num_limbs), capacity_(num_limbs), is_negative_(false) {
    if (capacity_ > 0) {
        limbs_ = std::make_unique<uint64_t[]>(capacity_);
        if (zero_initialize) {
            std::fill(limbs_.get(), limbs_.get() + capacity_, 0);
        }
    }
}

BigInt::BigInt(const BigInt& other)
    : size_(other.size_), capacity_(other.size_), is_negative_(other.is_negative_) {
    if (capacity_ > 0) {
        limbs_ = std::make_unique<uint64_t[]>(capacity_);
        std::copy(other.limbs_.get(), other.limbs_.get() + size_, limbs_.get());
    }
}

BigInt& BigInt::operator=(const BigInt& other) {
    if (this == &other) return *this;
    if (capacity_ < other.size_) {
        limbs_ = std::make_unique<uint64_t[]>(other.size_);
        capacity_ = other.size_;
    }
    size_ = other.size_;
    is_negative_ = other.is_negative_;
    if (size_ > 0) {
        std::copy(other.limbs_.get(), other.limbs_.get() + size_, limbs_.get());
    }
    return *this;
}

BigInt::BigInt(BigInt&& other) noexcept
    : limbs_(std::move(other.limbs_)),
      size_(other.size_),
      capacity_(other.capacity_),
      is_negative_(other.is_negative_) {
    other.size_ = 0;
    other.capacity_ = 0;
    other.is_negative_ = false;
}

BigInt& BigInt::operator=(BigInt&& other) noexcept {
    if (this == &other) return *this;
    limbs_ = std::move(other.limbs_);
    size_ = other.size_;
    capacity_ = other.capacity_;
    is_negative_ = other.is_negative_;
    other.size_ = 0;
    other.capacity_ = 0;
    other.is_negative_ = false;
    return *this;
}


void BigInt::resize(size_t new_capacity) {
    if (new_capacity <= capacity_) return;
    auto new_limbs = std::make_unique<uint64_t[]>(new_capacity);
    if(size_ > 0) {
        std::copy(limbs_.get(), limbs_.get() + size_, new_limbs.get());
    }
    limbs_ = std::move(new_limbs);
    capacity_ = new_capacity;
}

void BigInt::strip_leading_zeros() {
    while (size_ > 0 && limbs_[size_ - 1] == 0) {
        size_--;
    }
    if (size_ == 0) {
        is_negative_ = false;
    }
}

int BigInt::compare_magnitude(const BigInt& other) const {
    if (size_ < other.size_) return -1;
    if (size_ > other.size_) return 1;
    if (size_ == 0) return 0;
    for (size_t i = size_; i > 0; --i) {
        if (limbs_[i - 1] < other.limbs_[i - 1]) return -1;
        if (limbs_[i - 1] > other.limbs_[i - 1]) return 1;
    }
    return 0;
}

BigInt BigInt::add_magnitude(const BigInt& a, const BigInt& b) {
    const BigInt& larger = (a.size_ >= b.size_) ? a : b;
    const BigInt& smaller = (a.size_ >= b.size_) ? b : a;
    BigInt result(larger.size_ + 1, false);
    unsigned char carry = 0;
    size_t i = 0;
    for (; i < smaller.size_; ++i) {
        carry = _addcarry_u64(carry, larger.limbs_[i], smaller.limbs_[i], reinterpret_cast<unsigned long long*>(&result.limbs_[i]));
    }
    for (; i < larger.size_; ++i) {
        carry = _addcarry_u64(carry, larger.limbs_[i], 0, reinterpret_cast<unsigned long long*>(&result.limbs_[i]));
    }
    if (carry) {
        result.limbs_[i] = 1;
        result.size_ = i + 1;
    } else {
        result.size_ = larger.size_;
    }
    result.strip_leading_zeros();
    return result;
}

BigInt BigInt::subtract_magnitude(const BigInt& a, const BigInt& b) {
    BigInt result(a.size_, false);
    unsigned char borrow = 0;
    size_t i = 0;
    for (; i < b.size_; ++i) {
        borrow = _subborrow_u64(borrow, a.limbs_[i], b.limbs_[i], reinterpret_cast<unsigned long long*>(&result.limbs_[i]));
    }
    for (; i < a.size_; ++i) {
        borrow = _subborrow_u64(borrow, a.limbs_[i], 0, reinterpret_cast<unsigned long long*>(&result.limbs_[i]));
    }
    result.size_ = a.size_;
    result.strip_leading_zeros();
    return result;
}

std::pair<BigInt, BigInt> BigInt::div_mod_magnitude(const BigInt& dividend, const BigInt& divisor) {
    if (divisor.is_zero()) throw std::runtime_error("Division by zero (magnitude).");
    if (dividend.compare_magnitude(divisor) < 0) {
        return {BigInt(int64_t(0)), dividend};
    }
    BigInt quotient(int64_t(0));
    BigInt remainder = dividend;
    size_t initial_shift = dividend.bit_length() - divisor.bit_length();
    BigInt temp_divisor = divisor << initial_shift;
    for(size_t i = 0; i <= initial_shift; ++i) {
        if (remainder.compare_magnitude(temp_divisor) >= 0) {
            remainder -= temp_divisor;
            quotient |= (BigInt(int64_t(1)) << (initial_shift - i));
        }
        temp_divisor >>= 1;
    }
    return {quotient, remainder};
}

BigInt BigInt::operator++(int) {
    BigInt temp = *this;
    BigInt one(1);
    *this += one;
    return temp;
}

BigInt BigInt::operator--(int) {
    BigInt temp = *this;
    BigInt one(1);
    *this -= one;
    return temp;
}

BigInt& BigInt::operator++() {
    BigInt one(1);
    *this += one;
    return *this;
}

BigInt& BigInt::operator--() {
    BigInt one(1);
    *this -= one;
    return *this;
}   

BigInt BigInt::operator-() const {
    if (is_zero()) return *this;
    BigInt result = *this;
    result.is_negative_ = !is_negative_;
    return result;
}

BigInt BigInt::operator+(const BigInt& other) const {
    if (is_negative_ == other.is_negative_) {
        BigInt result = add_magnitude(*this, other);
        result.is_negative_ = is_negative_;
        return result;
    } else {
        int mag_cmp = compare_magnitude(other);
        if (mag_cmp == 0) return BigInt(int64_t(0));
        if (mag_cmp > 0) {
            BigInt result = subtract_magnitude(*this, other);
            result.is_negative_ = is_negative_;
            return result;
        } else {
            BigInt result = subtract_magnitude(other, *this);
            result.is_negative_ = other.is_negative_;
            return result;
        }
    }
}
BigInt& BigInt::operator+=(const BigInt& other) { *this = *this + other; return *this; }

BigInt BigInt::operator-(const BigInt& other) const { return *this + (-other); }
BigInt& BigInt::operator-=(const BigInt& other) { *this = *this - other; return *this; }

namespace {
#include <cmath>
#include <complex>

constexpr size_t FFT_THRESHOLD = 1000000; // временно увеличено для диагностики fft_mul

// fft
void fft(std::complex<double>* a, size_t n, bool invert) {
    for (size_t i = 1, j = 0; i < n; ++i) {
        size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(a[i], a[j]);
    }
    for (size_t len = 2; len <= n; len <<= 1) {
        double ang = 2 * M_PI / len * (invert ? -1 : 1);
        std::complex<double> wlen(cos(ang), sin(ang));
        for (size_t i = 0; i < n; i += len) {
            std::complex<double> w(1);
            for (size_t j = 0; j < len / 2; ++j) {
                std::complex<double> u = a[i + j];
                std::complex<double> v = a[i + j + len / 2] * w;
                a[i + j] = u + v;
                a[i + j + len / 2] = u - v;
                w *= wlen;
            }
        }
    }
    if (invert) for (size_t i = 0; i < n; ++i) a[i] /= n;
}

// Умножение через FFT
void fft_mul(const uint64_t* a, size_t an, const uint64_t* b, size_t bn, uint64_t* out) {
    size_t n = 1;
    while (n < an + bn) n <<= 1;
    std::unique_ptr<std::complex<double>[]> fa(new std::complex<double>[n]{});
    std::unique_ptr<std::complex<double>[]> fb(new std::complex<double>[n]{});
    for (size_t i = 0; i < an; ++i) fa[i] = (double)a[i];
    for (size_t i = 0; i < bn; ++i) fb[i] = (double)b[i];
    fft(fa.get(), n, false);
    fft(fb.get(), n, false);
    for (size_t i = 0; i < n; ++i) fa[i] *= fb[i];
    fft(fa.get(), n, true);
    // Собираем результат с переносами 
    std::unique_ptr<uint64_t[]> res(new uint64_t[n]{});
    double LIMB_BASE = 18446744073709551616.0; // 2^64
    int64_t carry = 0;
    for (size_t i = 0; i < n; ++i) {
        double val = std::round(fa[i].real()) + carry;
        carry = (int64_t)(val / LIMB_BASE);
        res[i] = (uint64_t)(val - carry * LIMB_BASE);
    }
    for (size_t i = 0; i < n; ++i) out[i] = res[i];
}
}

constexpr size_t KARATSUBA_THRESHOLD = 32; // по limb-ам (64 бита)

void schoolbook_mul(const uint64_t* a, size_t an, const uint64_t* b, size_t bn, uint64_t* out) {
    for (size_t i = 0; i < an + bn; ++i) out[i] = 0;
    for (size_t i = 0; i < an; ++i) {
        unsigned __int128 carry = 0;
#if defined(__AVX2__)
        if ((bn % 4 == 0) && ((uintptr_t)(b) % 32 == 0) && ((uintptr_t)(out + i) % 32 == 0)) {
            __m256i a_vec = _mm256_set1_epi64x(a[i]);
            size_t j = 0;
            for (; j + 3 < bn; j += 4) {
                __m256i b_vec = _mm256_load_si256((const __m256i*)(b + j));
                __m256i out_vec = _mm256_load_si256((__m256i*)(out + i + j));
                // Младшие 64 бита каждого lane: a[i] * b[j..j+3]
                uint64_t tmp[4];
                for (int k = 0; k < 4; ++k) tmp[k] = a[i] * b[j + k] + ((uint64_t*)&out_vec)[k];
                for (int k = 0; k < 4; ++k) ((uint64_t*)&out_vec)[k] = tmp[k];
                _mm256_store_si256((__m256i*)(out + i + j), out_vec);
            }
            // Остаток — обычным способом
            for (; j < bn; ++j) {
                unsigned __int128 product = (unsigned __int128)a[i] * b[j] + out[i + j] + carry;
                out[i + j] = (uint64_t)product;
                carry = product >> 64;
            }
        } else
#endif
        {
            for (size_t j = 0; j < bn; ++j) {
                unsigned __int128 product = (unsigned __int128)a[i] * b[j] + out[i + j] + carry;
                out[i + j] = (uint64_t)product;
                carry = product >> 64;
            }
        }
        out[i + bn] += (uint64_t)carry;
    }
}

void karatsuba_mul(const uint64_t* a, size_t an, const uint64_t* b, size_t bn, uint64_t* out, uint64_t* buf) {
    if (an <= KARATSUBA_THRESHOLD) {
        schoolbook_mul(a, an, b, bn, out);
        return;
    }
    size_t n = an;
    size_t k = n / 2;
    const uint64_t* a0 = a;
    const uint64_t* a1 = a + k;
    const uint64_t* b0 = b;
    const uint64_t* b1 = b + k;
    uint64_t* z0 = buf;
    uint64_t* z1 = buf + 2 * k;
    uint64_t* z2 = buf + 4 * k;
    // z0 = a0 * b0
    schoolbook_mul(a0, k, b0, k, z0);
    // z2 = a1 * b1
    schoolbook_mul(a1, k, b1, k, z2);
    // (a0+a1), (b0+b1)
    uint64_t* a_sum = buf + 6 * k;
    uint64_t* b_sum = buf + 7 * k;
    for (size_t i = 0; i < k; ++i) {
        a_sum[i] = a0[i] + a1[i];
        b_sum[i] = b0[i] + b1[i];
    }
    // z1 = (a0+a1)*(b0+b1)
    schoolbook_mul(a_sum, k, b_sum, k, z1);
    // z1 = z1 - z0 - z2
    for (size_t i = 0; i < 2 * k; ++i) {
        uint64_t t = z1[i];
        t -= z0[i];
        t -= z2[i];
        z1[i] = t;
    }
    // out = z0 + (z1 << (k*64)) + (z2 << (2*k*64))
    for (size_t i = 0; i < 2 * n; ++i) out[i] = 0;
    // Сложение с переносом для out += z0, z1, z2
    unsigned __int128 carry = 0;
    for (size_t i = 0; i < 2 * k; ++i) {
        unsigned __int128 sum = (unsigned __int128)out[i] + z0[i] + carry;
        out[i] = (uint64_t)sum;
        carry = sum >> 64;
    }
    // propagate carry
    for (size_t i = 2 * k; carry && i < 2 * n; ++i) {
        unsigned __int128 sum = (unsigned __int128)out[i] + carry;
        out[i] = (uint64_t)sum;
        carry = sum >> 64;
    }

    carry = 0;
    for (size_t i = 0; i < 2 * k; ++i) {
        unsigned __int128 sum = (unsigned __int128)out[i + k] + z1[i] + carry;
        out[i + k] = (uint64_t)sum;
        carry = sum >> 64;
    }
    for (size_t i = 2 * k + k; carry && i < 2 * n; ++i) {
        unsigned __int128 sum = (unsigned __int128)out[i] + carry;
        out[i] = (uint64_t)sum;
        carry = sum >> 64;
    }

    carry = 0;
    for (size_t i = 0; i < 2 * k; ++i) {
        unsigned __int128 sum = (unsigned __int128)out[i + 2 * k] + z2[i] + carry;
        out[i + 2 * k] = (uint64_t)sum;
        carry = sum >> 64;
    }
    for (size_t i = 2 * k + 2 * k; carry && i < 2 * n; ++i) {
        unsigned __int128 sum = (unsigned __int128)out[i] + carry;
        out[i] = (uint64_t)sum;
        carry = sum >> 64;
    }
}

BigInt BigInt::operator*(const BigInt& other) const {
    if (is_zero() || other.is_zero()) return BigInt(int64_t(0));
    size_t n = std::max(size_, other.size_);
    // FFT для очень больших чисел
    if (n > FFT_THRESHOLD) {
        size_t out_limbs = size_ + other.size_ + 2;
        std::unique_ptr<uint64_t[]> out(new uint64_t[out_limbs]{});
        fft_mul(limbs_.get(), size_, other.limbs_.get(), other.size_, out.get());
        BigInt result(out_limbs, false);
        for (size_t i = 0; i < out_limbs; ++i) result.limbs_[i] = out[i];
        result.size_ = size_ + other.size_;
        result.is_negative_ = (is_negative_ != other.is_negative_);
        result.strip_leading_zeros();
        return result;
    }
    size_t n2 = 1;
    while (n2 < n) n2 <<= 1;
    if (n2 <= KARATSUBA_THRESHOLD) {
        BigInt result(size_ + other.size_, true);
        schoolbook_mul(limbs_.get(), size_, other.limbs_.get(), other.size_, result.limbs_.get());
        result.size_ = size_ + other.size_;
        result.is_negative_ = (is_negative_ != other.is_negative_);
        result.strip_leading_zeros();
        return result;
    }
    // karatsuba: выделяем буферы вручную
    size_t out_limbs = 2 * n2;
    std::unique_ptr<uint64_t[]> a2(new uint64_t[n2]{});
    std::unique_ptr<uint64_t[]> b2(new uint64_t[n2]{});
    for (size_t i = 0; i < size_; ++i) a2[i] = limbs_[i];
    for (size_t i = 0; i < other.size_; ++i) b2[i] = other.limbs_[i];
    std::unique_ptr<uint64_t[]> out(new uint64_t[out_limbs]{});
    std::unique_ptr<uint64_t[]> buf(new uint64_t[8 * (n2 / 2)]{}); // karatsuba temp
    karatsuba_mul(a2.get(), n2, b2.get(), n2, out.get(), buf.get());
    BigInt result(2 * n2, false);
    for (size_t i = 0; i < 2 * n2; ++i) result.limbs_[i] = out[i];
    result.size_ = size_ + other.size_;
    result.is_negative_ = (is_negative_ != other.is_negative_);
    result.strip_leading_zeros();
    return result;
}
BigInt& BigInt::operator*=(const BigInt& other) { *this = *this * other; return *this; }

BigInt BigInt::operator/(const BigInt& other) const {
    if (other.is_zero()) throw std::runtime_error("Division by zero.");
    if (is_zero()) return BigInt(int64_t(0));
    auto result_pair = div_mod_magnitude(this->abs(), other.abs());
    BigInt quotient = result_pair.first;
    if (!quotient.is_zero() && (is_negative_ != other.is_negative_)) {
        quotient.is_negative_ = true;
    }
    return quotient;
}
BigInt& BigInt::operator/=(const BigInt& other) { *this = *this / other; return *this; }

BigInt BigInt::operator%(const BigInt& other) const {
    if (other.is_zero()) throw std::runtime_error("Division by zero.");
    if (is_zero()) return BigInt(int64_t(0));
    auto result_pair = div_mod_magnitude(this->abs(), other.abs());
    BigInt remainder = result_pair.second;
    if (!remainder.is_zero() && is_negative_) {
        remainder.is_negative_ = true;
    }
    return remainder;
}
BigInt& BigInt::operator%=(const BigInt& other) { *this = *this % other; return *this; }

BigInt BigInt::operator<<(size_t bits) const { BigInt result = *this; result <<= bits; return result; }
BigInt& BigInt::operator<<=(size_t bits) {
    if (bits == 0 || is_zero()) return *this;
    const size_t limb_shift = bits / 64;
    const size_t bit_shift = bits % 64;
    const size_t old_size = size_;
    size_t new_size = old_size + limb_shift;
    if (bit_shift > 0 && old_size > 0 && (limbs_[old_size - 1] >> (64 - bit_shift)) > 0) {
        new_size++;
    }
    if (capacity_ < new_size) resize(new_size);

    if (bit_shift == 0) {
        std::move_backward(limbs_.get(), limbs_.get() + old_size, limbs_.get() + new_size);
    } else {
        if (new_size > old_size + limb_shift) {
             limbs_[new_size - 1] = limbs_[old_size - 1] >> (64 - bit_shift);
        }
        for (size_t i = old_size; i > 0; --i) {
            uint64_t val = limbs_[i - 1];
            uint64_t carry = (i > 1) ? (limbs_[i - 2] >> (64 - bit_shift)) : 0;
            limbs_[i - 1 + limb_shift] = (val << bit_shift) | carry;
        }
    }
    std::fill(limbs_.get(), limbs_.get() + limb_shift, 0);
    size_ = new_size;
    strip_leading_zeros();
    return *this;
}

BigInt BigInt::operator>>(size_t bits) const { BigInt result = *this; result >>= bits; return result; }
BigInt& BigInt::operator>>=(size_t bits) {
    if (bits == 0 || is_zero()) return *this;
    const size_t limb_shift = bits / 64;
    const size_t bit_shift = bits % 64;
    if (limb_shift >= size_) { *this = BigInt(int64_t(0)); return *this; }
    const size_t new_size = size_ - limb_shift;
    if (bit_shift == 0) {
        std::move(limbs_.get() + limb_shift, limbs_.get() + size_, limbs_.get());
    } else {
        for (size_t i = 0; i < new_size; ++i) {
            uint64_t lower = limbs_[i + limb_shift];
            uint64_t upper = (i + limb_shift + 1 < size_) ? limbs_[i + limb_shift + 1] : 0;
            limbs_[i] = (lower >> bit_shift) | (upper << (64 - bit_shift));
        }
    }
    size_ = new_size;
    strip_leading_zeros();
    return *this;
}

BigInt BigInt::operator&(const BigInt& other) const {
    size_t n = std::max(size_, other.size_);
    auto get_twos = [n](const BigInt& x, std::unique_ptr<uint64_t[]>& out) {
        for (size_t i = 0; i < n; ++i) out[i] = (i < x.size_) ? x.limbs_[i] : 0;
        if (x.is_negative_) {
            for (size_t i = 0; i < n; ++i) out[i] = ~out[i];
            uint64_t carry = 1;
            for (size_t i = 0; i < n; ++i) {
                uint64_t sum = out[i] + carry;
                carry = (sum < out[i]);
                out[i] = sum;
                if (!carry) break;
            }
        }
    };
    std::unique_ptr<uint64_t[]> a(new uint64_t[n]{});
    std::unique_ptr<uint64_t[]> b(new uint64_t[n]{});
    get_twos(*this, a);
    get_twos(other, b);
    std::unique_ptr<uint64_t[]> res(new uint64_t[n]{});
    for (size_t i = 0; i < n; ++i) res[i] = a[i] & b[i];
    bool neg = is_negative_ && other.is_negative_;
    if (neg) {
        for (size_t i = 0; i < n; ++i) res[i] = ~res[i];
        uint64_t carry = 1;
        for (size_t i = 0; i < n; ++i) {
            uint64_t sum = res[i] + carry;
            carry = (sum < res[i]);
            res[i] = sum;
            if (!carry) break;
        }
    }
    BigInt out;
    out.resize(n);
    for (size_t i = 0; i < n; ++i) out.limbs_[i] = res[i];
    out.size_ = n;
    out.strip_leading_zeros();
    out.is_negative_ = neg && !out.is_zero();
    return out;
}
BigInt& BigInt::operator&=(const BigInt& other) { *this = *this & other; return *this; }

BigInt BigInt::operator|(const BigInt& other) const {
    size_t n = std::max(size_, other.size_);
    auto get_twos = [n](const BigInt& x, std::unique_ptr<uint64_t[]>& out) {
        for (size_t i = 0; i < n; ++i) out[i] = (i < x.size_) ? x.limbs_[i] : 0;
        if (x.is_negative_) {
            for (size_t i = 0; i < n; ++i) out[i] = ~out[i];
            uint64_t carry = 1;
            for (size_t i = 0; i < n; ++i) {
                uint64_t sum = out[i] + carry;
                carry = (sum < out[i]);
                out[i] = sum;
                if (!carry) break;
            }
        }
    };
    std::unique_ptr<uint64_t[]> a(new uint64_t[n]{});
    std::unique_ptr<uint64_t[]> b(new uint64_t[n]{});
    get_twos(*this, a);
    get_twos(other, b);
    std::unique_ptr<uint64_t[]> res(new uint64_t[n]{});
    for (size_t i = 0; i < n; ++i) res[i] = a[i] | b[i];
    bool neg = is_negative_ || other.is_negative_;
    if (neg) {
        for (size_t i = 0; i < n; ++i) res[i] = ~res[i];
        uint64_t carry = 1;
        for (size_t i = 0; i < n; ++i) {
            uint64_t sum = res[i] + carry;
            carry = (sum < res[i]);
            res[i] = sum;
            if (!carry) break;
        }
    }
    BigInt out;
    out.resize(n);
    for (size_t i = 0; i < n; ++i) out.limbs_[i] = res[i];
    out.size_ = n;
    out.strip_leading_zeros();
    out.is_negative_ = neg && !out.is_zero();
    return out;
}
BigInt& BigInt::operator|=(const BigInt& other) { *this = *this | other; return *this; }

BigInt BigInt::operator^(const BigInt& other) const {
    size_t n = std::max(size_, other.size_);
    auto get_twos = [n](const BigInt& x, std::unique_ptr<uint64_t[]>& out) {
        for (size_t i = 0; i < n; ++i) out[i] = (i < x.size_) ? x.limbs_[i] : 0;
        if (x.is_negative_) {
            for (size_t i = 0; i < n; ++i) out[i] = ~out[i];
            uint64_t carry = 1;
            for (size_t i = 0; i < n; ++i) {
                uint64_t sum = out[i] + carry;
                carry = (sum < out[i]);
                out[i] = sum;
                if (!carry) break;
            }
        }
    };
    std::unique_ptr<uint64_t[]> a(new uint64_t[n]{});
    std::unique_ptr<uint64_t[]> b(new uint64_t[n]{});
    get_twos(*this, a);
    get_twos(other, b);
    std::unique_ptr<uint64_t[]> res(new uint64_t[n]{});
    for (size_t i = 0; i < n; ++i) res[i] = a[i] ^ b[i];
    bool neg = (is_negative_ != other.is_negative_);
    if (neg) {
        for (size_t i = 0; i < n; ++i) res[i] = ~res[i];
        uint64_t carry = 1;
        for (size_t i = 0; i < n; ++i) {
            uint64_t sum = res[i] + carry;
            carry = (sum < res[i]);
            res[i] = sum;
            if (!carry) break;
        }
    }
    BigInt out;
    out.resize(n);
    for (size_t i = 0; i < n; ++i) out.limbs_[i] = res[i];
    out.size_ = n;
    out.strip_leading_zeros();
    out.is_negative_ = neg && !out.is_zero();
    return out;
}
BigInt& BigInt::operator^=(const BigInt& other) { *this = *this ^ other; return *this; }

bool BigInt::operator==(const BigInt& other) const {
    if (is_zero() && other.is_zero()) return true;
    return is_negative_ == other.is_negative_ && compare_magnitude(other) == 0;
}
bool BigInt::operator!=(const BigInt& other) const { return !(*this == other); }
bool BigInt::operator<(const BigInt& other) const {
    if (is_negative_ != other.is_negative_) return is_negative_;
    if (is_negative_) return compare_magnitude(other) > 0;
    else return compare_magnitude(other) < 0;
}
bool BigInt::operator>(const BigInt& other) const { return other < *this; }
bool BigInt::operator<=(const BigInt& other) const { return !(other < *this); }
bool BigInt::operator>=(const BigInt& other) const { return !(*this < other); }

std::string BigInt::to_hex_string() const {
    if (is_zero()) return "0x0";
    std::stringstream ss;
    ss << std::hex;
    ss << limbs_[size_ - 1];
    for (size_t i = size_ - 1; i > 0; --i) {
        ss << std::setfill('0') << std::setw(16) << limbs_[i - 1];
    }
    return (is_negative_ ? "-" : "") + std::string("0x") + ss.str();
}

std::string BigInt::to_dec_string() const {
    if (is_zero()) return "0";
    std::string dec_str;
    BigInt temp = this->abs();
    BigInt ten(10);
    while (!temp.is_zero()) {
        auto pair = div_mod_magnitude(temp, ten);
        temp = pair.first;
        dec_str += std::to_string(pair.second.is_zero() ? 0 : pair.second.limbs_[0]);
    }
    if (is_negative_) dec_str += '-';
    std::reverse(dec_str.begin(), dec_str.end());
    return dec_str;
}

bool BigInt::is_zero() const { return size_ == 0; }
bool BigInt::is_negative() const { return is_negative_ && !is_zero(); }
size_t BigInt::bit_length() const {
    if (is_zero()) return 0;
    size_t top_limb_bits = 0;
    uint64_t top_limb = limbs_[size_ - 1];
    top_limb_bits = 64 - __builtin_clzll(top_limb); // Используем встроенную функцию компилятора для скорости
    return ((size_ - 1) * 64) + top_limb_bits;
}
BigInt BigInt::abs() const {
    BigInt result = *this;
    result.is_negative_ = false;
    return result;
}

} // namespace bignum