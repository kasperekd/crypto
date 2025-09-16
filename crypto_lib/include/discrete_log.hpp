#pragma once

#include "bignum/bignum.hpp"
#include <optional>

using bignum::BigInt;

// If debug==true the function may print diagnostic information to stdout.
std::optional<BigInt> discrete_log_bsgs(const BigInt& a, const BigInt& y, const BigInt& p, bool debug = false);

