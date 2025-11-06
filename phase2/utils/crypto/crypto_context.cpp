#include "crypto_context.hpp"

#if HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

namespace crypto {

void CryptoContext::set_symmetric_key(const std::vector<unsigned char>& key_bytes) {
    key_ = key_bytes;
    ready_ = !key_.empty();
}

bool CryptoContext::encrypt(const std::string &plain, std::string &cipher_out) {
    if (!ready_) return false;
#if HAVE_OPENSSL
    unsigned char nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (ok != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), nullptr);
    if (ok != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    ok = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce);
    if (ok != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    std::string ciphertext;
    ciphertext.resize(plain.size());
    int out_len = 0;
    ok = EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &out_len,
                           reinterpret_cast<const unsigned char*>(plain.data()), (int)plain.size());
    if (ok != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    int tmp_len = 0;
    ok = EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + out_len, &tmp_len);
    if (ok != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    out_len += tmp_len;
    ciphertext.resize(out_len);
    unsigned char tag[16];
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1) return false;
    auto to_hex = [](const unsigned char* data, size_t len) {
        static const char* hex = "0123456789abcdef";
        std::string out; out.reserve(len*2);
        for (size_t i=0;i<len;++i){ unsigned char b=data[i]; out.push_back(hex[b>>4]); out.push_back(hex[b&0x0F]); }
        return out;
    };
    cipher_out = to_hex(nonce, sizeof(nonce)) + ':' + to_hex(reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) + ':' + to_hex(tag, sizeof(tag));
    return true;
#else
    cipher_out = plain; // insecure fallback
    return true;
#endif
}

bool CryptoContext::decrypt(const std::string &cipher, std::string &plain_out) {
    if (!ready_) return false;
#if HAVE_OPENSSL
    auto from_hex = [](const std::string &hex) -> std::vector<unsigned char> {
        if (hex.size()%2!=0) return {};
        std::vector<unsigned char> out(hex.size()/2);
        for (size_t i=0;i<hex.size(); i+=2){
            auto h = [](char c){ if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return 255; };
            unsigned v1=h(hex[i]); unsigned v2=h(hex[i+1]); if(v1==255||v2==255) return {}; out[i/2]=(unsigned char)((v1<<4)|v2);
        }
        return out;
    };
    size_t first = cipher.find(':');
    if (first==std::string::npos) return false;
    size_t second = cipher.find(':', first+1);
    if (second==std::string::npos) return false;
    std::string nonce_hex = cipher.substr(0, first);
    std::string ct_hex = cipher.substr(first+1, second-first-1);
    std::string tag_hex = cipher.substr(second+1);
    auto nonce = from_hex(nonce_hex);
    auto ct = from_hex(ct_hex);
    auto tag = from_hex(tag_hex);
    if (nonce.size()!=12 || tag.size()!=16 || ct.empty()) return false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (ok != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr);
    if (ok != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    ok = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce.data());
    if (ok != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    std::string plain; plain.resize(ct.size());
    int out_len=0;
    ok = EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plain[0]), &out_len, ct.data(), (int)ct.size());
    if (ok != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data());
    if (ok != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    int tmp_len=0;
    ok = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plain[0])+out_len, &tmp_len);
    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1) return false; // auth failed
    out_len += tmp_len;
    plain.resize(out_len);
    plain_out = plain;
    return true;
#else
    plain_out = cipher; // insecure fallback
    return true;
#endif
}

} // namespace crypto
