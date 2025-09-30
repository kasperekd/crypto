
#include "crypto_lib_boost/vernam_cipher.hpp"
#include "crypto_lib_boost/prime_utils.hpp"
#include "crypto_lib_boost/file_handler.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <functional>

namespace vernam_cipher {

VernamKeys generate_keys(size_t p_bits) {
	VernamKeys out;
	if (p_bits < 16) p_bits = 16;
	out.p = prime_utils::generate_prime((int)p_bits);
	out.g = BigInt(2);
	// private exponents
	out.xa = prime_utils::generate_coprime(out.p);
	out.xb = prime_utils::generate_coprime(out.p);
	out.pa = bignum::mod_exp(out.g, out.xa, out.p);
	out.pb = bignum::mod_exp(out.g, out.xb, out.p);
	out.shared = bignum::mod_exp(out.pb, out.xa, out.p);
	return out;
}

static std::vector<unsigned char> bigint_to_bytes(const BigInt& x) {
	std::string dec = x.str();
	// simple conversion: treat decimal string bytes as seed
	return std::vector<unsigned char>(dec.begin(), dec.end());
}

// keystream generator: repeat hashing of (seed + counter) using std::hash
static void fill_keystream(const BigInt& shared, std::vector<unsigned char>& out, size_t needed) {
	std::string seed_str = shared.str();
	size_t pos = 0;
	std::hash<std::string> h;
	uint64_t counter = 0;
	while (out.size() < needed) {
		std::string s = seed_str + ">" + std::to_string(counter++);
		uint64_t v = h(s);
		// expand 8 bytes
		for (int i = 0; i < 8 && out.size() < needed; ++i) {
			out.push_back((unsigned char)((v >> (8*i)) & 0xFF));
		}
	}
}

void save_keys_to_files(const VernamKeys& keys, const std::string& basename) {
	// save private key (includes xa and p,g)
	std::ostringstream priv;
	priv << "p:" << file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.p.str()))) << "\n";
	priv << "g:" << file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.g.str()))) << "\n";
	priv << "xa:" << file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.xa.str()))) << "\n";
	file_handler::write_text_file(basename + ".key", priv.str());

	std::ostringstream pub;
	pub << "p:" << file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.p.str()))) << "\n";
	pub << "g:" << file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.g.str()))) << "\n";
	pub << "pb:" << file_handler::bytes_to_str(file_handler::to_base64(file_handler::str_to_bytes(keys.pb.str()))) << "\n";
	file_handler::write_text_file(basename + ".pub", pub.str());
}

VernamKeys load_public_keys(const std::string& pubpath) {
	VernamKeys out;
	std::string content = file_handler::read_text_file(pubpath);
	std::istringstream iss(content);
	std::string line;
	while (std::getline(iss, line)) {
		if (line.rfind("p:", 0) == 0) {
			std::string b64 = line.substr(2);
			out.p = BigInt(file_handler::bytes_to_str(file_handler::from_base64(b64)));
		} else if (line.rfind("g:", 0) == 0) {
			std::string b64 = line.substr(2);
			out.g = BigInt(file_handler::bytes_to_str(file_handler::from_base64(b64)));
		} else if (line.rfind("pb:", 0) == 0) {
			std::string b64 = line.substr(3);
			out.pb = BigInt(file_handler::bytes_to_str(file_handler::from_base64(b64)));
		}
	}
	return out;
}

VernamKeys load_private_keys(const std::string& keypath) {
	VernamKeys out;
	std::string content = file_handler::read_text_file(keypath);
	std::istringstream iss(content);
	std::string line;
	while (std::getline(iss, line)) {
		if (line.rfind("p:", 0) == 0) {
			std::string b64 = line.substr(2);
			out.p = BigInt(file_handler::bytes_to_str(file_handler::from_base64(b64)));
		} else if (line.rfind("g:", 0) == 0) {
			std::string b64 = line.substr(2);
			out.g = BigInt(file_handler::bytes_to_str(file_handler::from_base64(b64)));
		} else if (line.rfind("xa:", 0) == 0) {
			std::string b64 = line.substr(3);
			out.xa = BigInt(file_handler::bytes_to_str(file_handler::from_base64(b64)));
		}
	}
	// compute public and shared if possible
	if (out.xa != 0 && out.p != 0 && out.g != 0) {
		out.pa = bignum::mod_exp(out.g, out.xa, out.p);
	}
	return out;
}

std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data, const BigInt& p, const BigInt& g, const BigInt& xa, const BigInt& pb) {
	// derive shared: shared = pb^{xa} mod p
	BigInt shared = bignum::mod_exp(pb, xa, p);
	std::vector<unsigned char> keystream;
	fill_keystream(shared, keystream, data.size());
	std::vector<unsigned char> out(data.size());
	for (size_t i = 0; i < data.size(); ++i) out[i] = data[i] ^ keystream[i];
	return out;
}

std::vector<unsigned char> decrypt(const std::vector<unsigned char>& data, const BigInt& p, const BigInt& g, const BigInt& xb, const BigInt& pa) {
	// derive shared: shared = pa^{xb} mod p
	BigInt shared = bignum::mod_exp(pa, xb, p);
	std::vector<unsigned char> keystream;
	fill_keystream(shared, keystream, data.size());
	std::vector<unsigned char> out(data.size());
	for (size_t i = 0; i < data.size(); ++i) out[i] = data[i] ^ keystream[i];
	return out;
}

} // namespace vernam_cipher

