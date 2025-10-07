#include "crypto_lib_boost/signature_interface.hpp"
#include "crypto_lib_boost/sha256.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include "crypto_lib_boost/prime_utils.hpp"
#include "crypto_lib_boost/bignum.hpp"
#include <stdexcept>
#include <fstream>
#include <boost/multiprecision/miller_rabin.hpp>

namespace signature {

// y = a^x mod p
static void save_gost_keys(const BigInt &p, const BigInt &q, const BigInt &a, const BigInt &y, const BigInt &x, const std::string &base) {
    std::string p_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(p.str())));
    std::string q_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(q.str())));
    std::string a_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(a.str())));
    std::string y_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(y.str())));
    std::string x_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(x.str())));

    std::ofstream pub(base + ".pub");
    if (!pub.is_open()) throw std::runtime_error("Cannot create public key file");
    pub << "p:" << p_b64 << "\n";
    pub << "q:" << q_b64 << "\n";
    pub << "a:" << a_b64 << "\n";
    pub << "y:" << y_b64 << "\n";
    pub.close();

    std::ofstream priv(base + ".key");
    if (!priv.is_open()) throw std::runtime_error("Cannot create private key file");
    priv << "p:" << p_b64 << "\n";
    priv << "q:" << q_b64 << "\n";
    priv << "x:" << x_b64 << "\n";
    priv.close();
}

static void load_gost_public(const std::string &path, BigInt &p, BigInt &q, BigInt &a, BigInt &y) {
    std::ifstream f(path);
    if (!f.is_open()) throw std::runtime_error("Cannot open public key: " + path);
    std::string line;
    while (std::getline(f, line)) {
        auto pos = line.find(':'); if (pos==std::string::npos) continue;
        std::string k = line.substr(0,pos);
        std::string v = line.substr(pos+1);
        BigInt val(file_handler::bytes_to_str(file_handler::from_base64(v)));
        if (k=="p") p = val;
        else if (k=="q") q = val;
        else if (k=="a") a = val;
        else if (k=="y") y = val;
    }
}

static void load_gost_private(const std::string &path, BigInt &p, BigInt &q, BigInt &x) {
    std::ifstream f(path);
    if (!f.is_open()) throw std::runtime_error("Cannot open private key: " + path);
    std::string line;
    while (std::getline(f, line)) {
        auto pos = line.find(':'); if (pos==std::string::npos) continue;
        std::string k = line.substr(0,pos);
        std::string v = line.substr(pos+1);
        BigInt val(file_handler::bytes_to_str(file_handler::from_base64(v)));
        if (k=="p") p = val;
        else if (k=="q") q = val;
        else if (k=="x") x = val;
    }
}

KeyPair generate_gost_keys(int bits) {
    // bits parameter controls q size (commonly 256). We'll try to construct p = q*k + 1
    // where p is prime. This is a simple constructive approach (may take time for large sizes).
    BigInt q = prime_utils::generate_prime(bits);

    BigInt p;
    // pick k until p = q*k + 1 is prime; k should give p at least somewhat larger than q
    for (int attempt = 0; attempt < 20000; ++attempt) {
        BigInt k = prime_utils::generate_coprime(q);
        p = q * k + 1;
        // ensure p is odd and > q
        if (p <= q) continue;
        // primality test (miller-rabin wrapper in prime_utils)
        try {
            // generate_prime uses MR; reuse same test by attempting a MR test via generate_prime small wrapper
            // Instead of exposing MR test, we'll attempt to check primality by testing miller_rabin directly
            if (boost::multiprecision::miller_rabin_test(p, 25)) break;
        } catch(...) {
            // fallthrough
        }
    }

    if (p == 0) throw std::runtime_error("Failed to generate p for GOST keys");

    // choose a generator a of order q: find h and compute a = h^{(p-1)/q} mod p, a>1
    BigInt a(0);
    BigInt exp = (p - 1) / q;
    for (int htry = 2; htry < 10000; ++htry) {
        BigInt h = BigInt(htry);
        a = bignum::mod_exp(h, exp, p);
        if (a > 1) break;
    }
    if (a <= 1) throw std::runtime_error("Failed to find generator a for GOST");

    // private x in [1, q-1]
    BigInt x = prime_utils::generate_coprime(q);
    if (x >= q) x = x % (q - 1) + 1;

    BigInt y = bignum::mod_exp(a, x, p);

    save_gost_keys(p, q, a, y, x, "gost_sig");
    return {"gost_sig.key", "gost_sig.pub"};
}

std::vector<unsigned char> gost_sign_file(const std::string& priv_key_path, const std::string& file_path) {
    BigInt p, q, x;
    load_gost_private(priv_key_path, p, q, x);

    // compute hash e = SHA256(file) mod q
    auto digest = crypto_hash::sha256_of_file(file_path);
    BigInt e(0); for (unsigned char b : digest) e = e * 256 + (int)b;
    e = e % q;
    if (e == 0) e = 1;

    BigInt r(0), s(0);
    // load public parameter 'a' once from the corresponding .pub
    std::string pub_path = priv_key_path;
    if (pub_path.size() > 4 && pub_path.substr(pub_path.size()-4) == ".key") pub_path = pub_path.substr(0, pub_path.size()-4) + ".pub";
    else pub_path = pub_path + ".pub";
    BigInt pub_p, pub_q, a, y;
    load_gost_public(pub_path, pub_p, pub_q, a, y);

    for (int attempt = 0; attempt < 1000; ++attempt) {
        BigInt k = prime_utils::generate_coprime(q);
        if (k >= q) k = k % (q - 1) + 1;
        r = bignum::mod_exp(a, k, p) % q;
        if (r == 0) continue;
        s = (x * r + k * e) % q;
        if (s == 0) continue;
        break;
    }

    if (r == 0 || s == 0) throw std::runtime_error("Failed to produce GOST signature");
    std::string out = r.str() + ":" + s.str();
    return file_handler::str_to_bytes(out);
}

bool gost_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig) {
    BigInt p, q, a, y;
    load_gost_public(pub_key_path, p, q, a, y);
    std::string s = file_handler::bytes_to_str(sig);
    auto pos = s.find(':'); if (pos == std::string::npos) return false;
    BigInt r(s.substr(0,pos)); BigInt ss(s.substr(pos+1));
    if (r <= 0 || r >= q) return false;
    if (ss <= 0 || ss >= q) return false;

    auto digest = crypto_hash::sha256_of_file(file_path);
    BigInt e(0); for (unsigned char b : digest) e = e * 256 + (int)b;
    e = e % q;
    if (e == 0) e = 1;

    // canonical check: ensure bytes equal decimal "r:s"
    std::string canonical = r.str() + ":" + ss.str();
    if (file_handler::str_to_bytes(canonical) != sig) return false;

    // v = e^{-1} mod q
    BigInt v = prime_utils::modular_inverse(e, q);
    if (v == 0) return false;
    BigInt z1 = (ss * v) % q;
    BigInt z2 = ((q - r) * v) % q;
    BigInt u = (bignum::mod_exp(a, z1, p) * bignum::mod_exp(y, z2, p)) % p;
    u = u % q;
    return u == r;
}

} // namespace signature
