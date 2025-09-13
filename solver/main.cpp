# include <iostream>
# include <string>
# include <stdexcept>
# include "bignum/bignum.hpp"

int main() {
    bignum::BigInt a("100000000000000");
    bignum::BigInt b("100000");
    auto c = a / b;
    std::cout << "c (dec): " << c.to_dec_string() << std::endl;

    return 0;
}