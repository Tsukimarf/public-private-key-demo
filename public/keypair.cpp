/**
 * Public / Private Key Demo — C++ (OpenSSL)
 * Blockchain 101 context: secp256k1 + ECDSA + SHA-256
 *
 * Compile:  g++ -std=c++17 keypair.cpp -lssl -lcrypto -o keypair
 * Run:      ./keypair
 *
 * On Ubuntu:  sudo apt install libssl-dev
 * On macOS:   brew install openssl
 *             g++ -std=c++17 keypair.cpp -I$(brew --prefix openssl)/include \
 *                 -L$(brew --prefix openssl)/lib -lssl -lcrypto -o keypair
 */

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <memory>
#include <ctime>

// ─── Utilities ────────────────────────────────────────────────────────────────

std::string toHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

std::string bnToHex(const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

std::vector<uint8_t> sha256(const std::string& msg) {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const uint8_t*>(msg.c_str()), msg.size(), digest.data());
    return digest;
}

std::string isoTimestamp() {
    time_t now = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    return buf;
}

// ─── Key Record (database entry) ──────────────────────────────────────────────

struct KeyRecord {
    std::string id;
    std::string label;
    std::string privateKeyHex;
    std::string publicKeyX;
    std::string publicKeyY;
    std::string publicKeyHex;  // uncompressed: 04 + x + y
    std::string curve;
    std::string createdAt;
};

// ─── Signature ────────────────────────────────────────────────────────────────

struct Signature {
    std::string r;
    std::string s;
    bool        valid;
};

// ─── Key Generation ───────────────────────────────────────────────────────────

KeyRecord generateKeyPair(const std::string& label) {
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) throw std::runtime_error("EC_KEY_new_by_curve_name failed");

    if (EC_KEY_generate_key(key) != 1)
        throw std::runtime_error("EC_KEY_generate_key failed");

    // Private key
    const BIGNUM* priv = EC_KEY_get0_private_key(key);

    // Public key coordinates
    const EC_GROUP* group = EC_KEY_get0_group(key);
    const EC_POINT* pub   = EC_KEY_get0_public_key(key);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(group, pub, x, y, nullptr);

    KeyRecord rec;
    rec.id            = toHex([]{ uint8_t r[4]; RAND_bytes(r,4); return r; }(), 4);
    rec.label         = label;
    rec.privateKeyHex = bnToHex(priv);
    rec.publicKeyX    = bnToHex(x);
    rec.publicKeyY    = bnToHex(y);
    rec.publicKeyHex  = "04" + rec.publicKeyX + rec.publicKeyY;
    rec.curve         = "secp256k1";
    rec.createdAt     = isoTimestamp();

    BN_free(x);
    BN_free(y);
    EC_KEY_free(key);
    return rec;
}

// ─── Sign ─────────────────────────────────────────────────────────────────────

Signature signMessage(const std::string& privateKeyHex, const std::string& message) {
    // Restore key from hex
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* priv = nullptr;
    BN_hex2bn(&priv, privateKeyHex.c_str());
    EC_KEY_set_private_key(key, priv);

    // Reconstruct public key from private
    const EC_GROUP* group = EC_KEY_get0_group(key);
    EC_POINT* pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, nullptr, nullptr, nullptr);
    EC_KEY_set_public_key(key, pub);

    // Hash the message
    auto digest = sha256(message);

    // Sign
    ECDSA_SIG* sig = ECDSA_do_sign(digest.data(), digest.size(), key);
    if (!sig) throw std::runtime_error("ECDSA_do_sign failed");

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);

    Signature result;
    result.r     = bnToHex(r);
    result.s     = bnToHex(s);
    result.valid = true;

    ECDSA_SIG_free(sig);
    EC_POINT_free(pub);
    BN_free(priv);
    EC_KEY_free(key);
    return result;
}

// ─── Verify ───────────────────────────────────────────────────────────────────

bool verifySignature(const std::string& publicKeyHex,
                     const std::string& message,
                     const Signature&   sig) {
    EC_KEY*   key   = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_GROUP* group = const_cast<EC_GROUP*>(EC_KEY_get0_group(key));
    EC_POINT* pub   = EC_POINT_new(group);

    // Set public key from uncompressed hex
    BIGNUM* pubBN = nullptr;
    BN_hex2bn(&pubBN, publicKeyHex.c_str());
    EC_POINT_bn2point(group, pubBN, pub, nullptr);
    EC_KEY_set_public_key(key, pub);

    // Reconstruct signature
    ECDSA_SIG* ecSig = ECDSA_SIG_new();
    BIGNUM* r = nullptr;
    BIGNUM* s = nullptr;
    BN_hex2bn(&r, sig.r.c_str());
    BN_hex2bn(&s, sig.s.c_str());
    ECDSA_SIG_set0(ecSig, r, s);

    // Hash and verify
    auto digest = sha256(message);
    int  ok     = ECDSA_do_verify(digest.data(), digest.size(), ecSig, key);

    ECDSA_SIG_free(ecSig);
    BN_free(pubBN);
    EC_POINT_free(pub);
    EC_KEY_free(key);
    return ok == 1;
}

// ─── Key Database ─────────────────────────────────────────────────────────────

#include <vector>
#include <algorithm>

class KeyDatabase {
    std::vector<KeyRecord> records;
public:
    void add(const KeyRecord& rec) {
        records.push_back(rec);
    }

    KeyRecord* findById(const std::string& id) {
        auto it = std::find_if(records.begin(), records.end(),
            [&](const KeyRecord& r){ return r.id == id; });
        return it != records.end() ? &(*it) : nullptr;
    }

    std::vector<KeyRecord*> findByLabel(const std::string& label) {
        std::vector<KeyRecord*> out;
        for (auto& r : records)
            if (r.label == label) out.push_back(&r);
        return out;
    }

    size_t count() const { return records.size(); }

    // Print all keys (summary)
    void print() const {
        for (const auto& r : records) {
            std::cout << "[" << r.id << "] " << r.label
                      << " | " << r.curve
                      << " | " << r.createdAt << "\n"
                      << "  pub: " << r.publicKeyHex.substr(0, 32) << "...\n";
        }
    }
};

// ─── Main Demo ────────────────────────────────────────────────────────────────

int main() {
    std::cout << "=== Public/Private Key Demo (C++ / OpenSSL) ===\n\n";

    try {
        // 1. Generate key pair
        KeyRecord alice = generateKeyPair("Alice wallet");
        std::cout << "Generated key pair for: " << alice.label << "\n";
        std::cout << "Private: " << alice.privateKeyHex << "\n";
        std::cout << "Public:  04" << alice.publicKeyX.substr(0,16)
                  << "..." << "\n\n";

        // 2. Sign message
        std::string msg = "Send 1 BTC to Alice";
        Signature   sig = signMessage(alice.privateKeyHex, msg);
        std::cout << "Message: " << msg << "\n";
        std::cout << "r: " << sig.r << "\n";
        std::cout << "s: " << sig.s << "\n\n";

        // 3. Verify original
        bool valid = verifySignature(alice.publicKeyHex, msg, sig);
        std::cout << "Verify original : " << (valid ? "VALID" : "INVALID") << "\n";

        // 4. Verify tampered
        bool tampered = verifySignature(alice.publicKeyHex, msg + "!", sig);
        std::cout << "Verify tampered : " << (tampered ? "VALID" : "INVALID") << "\n\n";

        // 5. Database
        KeyDatabase db;
        db.add(alice);
        KeyRecord bob = generateKeyPair("Bob cold storage");
        db.add(bob);

        std::cout << "Key database (" << db.count() << " records):\n";
        db.print();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}