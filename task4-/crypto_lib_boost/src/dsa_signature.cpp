    #include "crypto_lib_boost/signature_interface.hpp"
    #include "crypto_lib_boost/sha256.hpp"
    #include "crypto_lib_boost/file_handler.hpp"
    #include "crypto_lib_boost/prime_utils.hpp"
    #include "crypto_lib_boost/bignum.hpp"
    #include <stdexcept>
    #include <fstream>
    #include <boost/multiprecision/miller_rabin.hpp>

    namespace signature {

    // r = (g^k mod p) mod q
    // s = k^{-1}(H + x*r) mod q

    static void save_dsa_keys(const BigInt &p, const BigInt &q, const BigInt &g, const BigInt &y, const BigInt &x, const std::string &base) {
        std::string p_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(p.str())));
        std::string q_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(q.str())));
        std::string g_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(g.str())));
        std::string y_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(y.str())));
        std::string x_b64 = file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(x.str())));

        std::ofstream pub(base + ".pub");
        if (!pub.is_open()) throw std::runtime_error("Cannot create public key file");
        pub << "p:" << p_b64 << "\n";
        pub << "q:" << q_b64 << "\n";
        pub << "g:" << g_b64 << "\n";
        pub << "y:" << y_b64 << "\n";
        pub.close();

        std::ofstream priv(base + ".key");
        if (!priv.is_open()) throw std::runtime_error("Cannot create private key file");
        priv << "p:" << p_b64 << "\n";
        priv << "q:" << q_b64 << "\n";
        priv << "x:" << x_b64 << "\n";
        priv.close();
    }

    static void load_dsa_public(const std::string &path, BigInt &p, BigInt &q, BigInt &g, BigInt &y) {
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
            else if (k=="g") g = val;
            else if (k=="y") y = val;
        }
    }

    static void load_dsa_private(const std::string &path, BigInt &p, BigInt &q, BigInt &x) {
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

    KeyPair generate_dsa_keys(int bits) {
        BigInt q = prime_utils::generate_prime(bits);
        BigInt p;
    // p = q*k + 1
        for (int attempt = 0; attempt < 20000; ++attempt) {
            BigInt k = prime_utils::generate_coprime(q);
            p = q * k + 1;
            if (p <= q) continue;
            try {
                if (boost::multiprecision::miller_rabin_test(p, 25)) break;
            } catch(...) {}
        }
        if (p == 0) throw std::runtime_error("Failed to generate p for DSA keys");

        BigInt g(0);
        BigInt exp = (p - 1) / q;
        for (int htry = 2; htry < 10000; ++htry) {
            BigInt h = BigInt(htry);
            g = bignum::mod_exp(h, exp, p);
            if (g > 1) break;
        }
        if (g <= 1) throw std::runtime_error("Failed to find generator g for DSA");

        BigInt x = prime_utils::generate_coprime(q);
        if (x >= q) x = x % (q - 1) + 1;
        BigInt y = bignum::mod_exp(g, x, p);

        save_dsa_keys(p, q, g, y, x, "dsa_sig");
        return {"dsa_sig.key", "dsa_sig.pub"};
    }

    std::vector<unsigned char> dsa_sign_file(const std::string& priv_key_path, const std::string& file_path) {
        BigInt p, q, x;
        load_dsa_private(priv_key_path, p, q, x);
        
        std::string pub_path = priv_key_path;
        if (pub_path.size() > 4 && pub_path.substr(pub_path.size()-4) == ".key") pub_path = pub_path.substr(0, pub_path.size()-4) + ".pub";
        else pub_path = pub_path + ".pub";
        BigInt pub_p, pub_q, g, y;
        load_dsa_public(pub_path, pub_p, pub_q, g, y);

        auto digest = crypto_hash::sha256_of_file(file_path);
        BigInt H(0); for (unsigned char b : digest) H = H * 256 + (int)b;
        H = H % q;
        if (H == 0) H = 1;

        BigInt r(0), s(0);
        for (int attempt = 0; attempt < 1000; ++attempt) {
            BigInt k = prime_utils::generate_coprime(q);
            if (k >= q) k = k % (q - 1) + 1;
            r = bignum::mod_exp(g, k, p) % q;
            if (r == 0) continue;
            BigInt k_inv = prime_utils::modular_inverse(k, q);
            if (k_inv == 0) continue;
            s = (k_inv * (H + x * r)) % q;
            if (s == 0) continue;
            break;
        }
        if (r == 0 || s == 0) throw std::runtime_error("Failed to produce DSA signature");
        std::string out = r.str() + ":" + s.str();
        return file_handler::str_to_bytes(out);
    }

    bool dsa_verify_file(const std::string& pub_key_path, const std::string& file_path, const std::vector<unsigned char>& sig) {
        BigInt p, q, g, y;
        load_dsa_public(pub_key_path, p, q, g, y);
        std::string s = file_handler::bytes_to_str(sig);
        auto pos = s.find(':'); if (pos == std::string::npos) return false;
        BigInt r(s.substr(0,pos)); BigInt ss(s.substr(pos+1));
        if (r <= 0 || r >= q) return false;
        if (ss <= 0 || ss >= q) return false;

        auto digest = crypto_hash::sha256_of_file(file_path);
        BigInt H(0); for (unsigned char b : digest) H = H * 256 + (int)b;
        H = H % q;
        if (H == 0) H = 1;

    std::string canonical = r.str() + ":" + ss.str();
    if (file_handler::str_to_bytes(canonical) != sig) return false;

        BigInt w = prime_utils::modular_inverse(ss, q);
        if (w == 0) return false;
        BigInt u1 = (H * w) % q;
        BigInt u2 = (r * w) % q;
        BigInt v = (bignum::mod_exp(g, u1, p) * bignum::mod_exp(y, u2, p)) % p;
        v = v % q;
        return v == r;
    }

    } // namespace signature