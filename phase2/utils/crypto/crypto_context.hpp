#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "config.hpp"

namespace crypto {

struct KeyMaterial {
    std::vector<unsigned char> key;   // symmetric key bytes
    std::vector<unsigned char> salt;  // optional HKDF salt
};

class CryptoContext {
public:
    CryptoContext() = default;
    bool ready() const noexcept { return ready_; }

    // Establish from raw symmetric key bytes
    void set_symmetric_key(const std::vector<unsigned char>& key_bytes);

    // Encrypt plaintext -> ciphertext (GCM planned). Returns false if not ready.
    bool encrypt(const std::string &plain, std::string &cipher_out);
    bool decrypt(const std::string &cipher, std::string &plain_out);

private:
    bool ready_{false};
    std::vector<unsigned char> key_;
};

} // namespace crypto
