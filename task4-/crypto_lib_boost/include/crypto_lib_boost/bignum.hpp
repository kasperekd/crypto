#ifndef BIGNUM_HPP
#define BIGNUM_HPP

#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;

namespace bignum {
    inline BigInt mod_exp(const BigInt& base, const BigInt& exponent, const BigInt& modulus) {
        return boost::multiprecision::powm(base, exponent, modulus);
    }

    inline BigInt gcd(const BigInt& a, const BigInt& b) {
        return boost::multiprecision::gcd(a, b);
    }

} // namespace bignum

#endif // BIGNUM_HPP