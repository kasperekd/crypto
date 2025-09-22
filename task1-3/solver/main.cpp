# include <iostream>
# include <string>
# include <stdexcept>
# include <chrono>
# include "bignum/bignum.hpp"

int main() {

    using bignum::BigInt;
    using namespace std;
    BigInt base("2");
    size_t exp = 2049;

    // Возведение в степень через цикл умножения
    auto t1 = std::chrono::high_resolution_clock::now();
    BigInt res_loop(1);
    for (size_t i = 0; i < exp; ++i) res_loop *= base;
    auto t2 = std::chrono::high_resolution_clock::now();
    auto dur_loop = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

    // Возведение в степень через pow
    t1 = std::chrono::high_resolution_clock::now();
    BigInt res_pow = base.pow(exp);
    t2 = std::chrono::high_resolution_clock::now();
    auto dur_pow = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

    cout << "base = " << base.to_dec_string() << "\nexp = " << exp << endl;
    cout << "\n[Цикл] Время: " << dur_loop << " мкс\n";
    cout << "[Цикл] Результат: " << res_loop.to_dec_string() << "  (len=" << res_loop.to_dec_string().size() << ")\n";
    cout << "\n[POW]  Время: " << dur_pow << " мкс\n";
    cout << "[POW]  Результат: " << res_pow.to_dec_string() << "  (len=" << res_pow.to_dec_string().size() << ")\n";
    cout << "\nРезультаты совпадают: " << (res_loop == res_pow ? "YES" : "NO") << endl;

    // auto last = res_loop * res_loop *res_loop *res_loop *res_loop *res_loop *res_loop *res_pow * BigInt("1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")*res_loop;
    // cout << "\nПроверка умножения: " << last.to_dec_string() << endl;

    // 6765494483396254450987387309920735429946252864637904696847373639558817794416220294752620832667297695078386001433763719183698710498635165476311194721403760866854609315513751149979355252414465884903609347942004475612618225130773741750727146788370933224738022152776317309397102092710233041864610889688192458318749254702421220562165273299325005463994120364497903320100000000000000000000

    // bignum::BigInt a("7000000000000000000000222000000000000000000000000");
    // bignum::BigInt b("26454");
    // size_t iterations = 100;
    // bignum::BigInt g = 1;
    // for (size_t i = 0; i < iterations; i++)
    // {
    //     g *= (a * 54 - 2 + b * a * b + (a - b * b * b * a * 34));

    // }

    // std::cout << "c (dec): " << g.to_dec_string() << std::endl;

    return 0;
}