#include <iostream>
#include "crypto_lib/diffie_hellman.hpp"
#include "crypto_lib.hpp"

using bignum::BigInt;

int main() {
    std::cout << "Diffie-Hellman demo\n";
    std::cout << "Options:\n 1) Manual input p,g,XA,XB\n 2) Generate parameters\nChoose: ";
    int opt = 0; std::cin >> opt;
    if (opt == 1) {
        std::string pstr, gstr, xastr, xbstr;
        std::cout << "p: "; std::cin >> pstr;
        std::cout << "g: "; std::cin >> gstr;
        std::cout << "XA: "; std::cin >> xastr;
        std::cout << "XB: "; std::cin >> xbstr;
        BigInt p(pstr), g(gstr), XA(xastr), XB(xbstr);
        BigInt PA = power_mod(g, XA, p);
        BigInt PB = power_mod(g, XB, p);
        BigInt shared = power_mod(PB, XA, p);
        std::cout << "PA=" << PA.to_dec_string() << "\n";
        std::cout << "PB=" << PB.to_dec_string() << "\n";
        std::cout << "shared=" << shared.to_dec_string() << "\n";
    } else {
        std::cout << "Generating small demo parameters (bits=32)...\n";
        auto params = dh_generate(32);
        std::cout << "p=" << params.p.to_dec_string() << "\n";
        std::cout << "g=" << params.g.to_dec_string() << "\n";
        std::cout << "XA=" << params.XA.to_dec_string() << "\n";
        std::cout << "XB=" << params.XB.to_dec_string() << "\n";
        std::cout << "PA=" << params.PA.to_dec_string() << "\n";
        std::cout << "PB=" << params.PB.to_dec_string() << "\n";
        std::cout << "shared=" << params.shared.to_dec_string() << "\n";
    }
    return 0;
}
