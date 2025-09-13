# include <iostream>
# include <string>
# include <stdexcept>
# include "bignum/bignum.hpp"

int main() {
    bignum::BigInt a("7000000000000000000000222000000000000000000000000");
    bignum::BigInt b("26454");
    size_t iterations = 100;
    bignum::BigInt g = 1;
    for (size_t i = 0; i < iterations; i++)
    {
        g *= (a * 54 - 2 + b * a * b + (a - b * b * b * a * 34));

    }

    std::cout << "c (dec): " << g.to_dec_string() << std::endl;

    return 0;
}