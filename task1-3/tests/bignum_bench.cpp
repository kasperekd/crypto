#include "bignum/bignum.hpp"
#include <chrono>
#include <iostream>
#include <random>
#include <vector>

using namespace bignum;
using namespace std;

// Генерация случайной строки числа длиной n цифр
string random_dec_string(size_t n) {
    static mt19937_64 rng(42);
    uniform_int_distribution<int> d(0, 9);
    string s;
    s += '1' + d(rng) % 9; // первая не 0
    for (size_t i = 1; i < n; ++i) s += '0' + d(rng);
    return s;
}

void bench_add(size_t digits, int iters) {
    string a = random_dec_string(digits);
    string b = random_dec_string(digits);
    BigInt x(a), y(b), z;
    auto t1 = chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) z = x + y;
    auto t2 = chrono::high_resolution_clock::now();
    cout << "add(" << digits << ") avg: "
         << chrono::duration_cast<chrono::microseconds>(t2-t1).count() / double(iters) << " us" << endl;
}

void bench_mul(size_t digits, int iters) {
    string a = random_dec_string(digits);
    string b = random_dec_string(digits);
    BigInt x(a), y(b), z;
    auto t1 = chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) z = x * y;
    auto t2 = chrono::high_resolution_clock::now();
    cout << "mul(" << digits << ") avg: "
         << chrono::duration_cast<chrono::microseconds>(t2-t1).count() / double(iters) << " us" << endl;
}

void bench_div(size_t digits, int iters) {
    string a = random_dec_string(digits);
    string b = random_dec_string(digits);
    // b не должен быть нулём
    if (b.find_first_not_of('0') == string::npos) b[0] = '1';
    BigInt x(a), y(b), z;
    auto t1 = chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) z = x / y;
    auto t2 = chrono::high_resolution_clock::now();
    cout << "div(" << digits << ") avg: "
         << chrono::duration_cast<chrono::microseconds>(t2-t1).count() / double(iters) << " us" << endl;
}

int main() {
    vector<size_t> sizes = {8, 32, 128, 512, 2048, 8192};
    int iters = 100;
    for (size_t d : sizes) bench_add(d, iters);
    for (size_t d : sizes) bench_mul(d, iters);
    for (size_t d : sizes) bench_div(d, iters);
    return 0;
}
