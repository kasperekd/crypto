#pragma once

#include "bignum/bignum.hpp"

using bignum::BigInt;

// Compute Diffie-Hellman shared secret from inputs (p, g, XA, XB).
// XA and XB are private exponents. Returns shared secret K = g^{XA*XB} mod p via
// computing KA = g^{XA} mod p, KB = g^{XB} mod p and K = KB^{XA} mod p.
BigInt dh_shared_from_private(const BigInt& p, const BigInt& g, const BigInt& XA, const BigInt& XB);

// Generate p,g, private keys XA,XB (using generate_random_prime for p), compute
// public keys and shared secret. Returns a tuple-like struct with values.
struct DHParams {
    BigInt p;
    BigInt g;
    BigInt XA;
    BigInt XB;
    BigInt PA; // public key g^XA mod p
    BigInt PB; // public key g^XB mod p
    BigInt shared; // shared secret
};

// Generate parameters with rough bit-size for p
// The function will attempt to pick a generator g in [2, p-2] and private keys
// XA,XB in [2, p-2].
DHParams dh_generate(size_t p_bits = 32);
