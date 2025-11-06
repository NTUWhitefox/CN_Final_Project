#include "handshake.hpp"

#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <string>

#if HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#endif

namespace crypto {

namespace {

bool recv_line_with_timeout(int fd, std::string &line, int timeout_sec = 2) {
    line.clear();
    std::string buf;
    char ch;
    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        timeval tv{timeout_sec, 0};
        int rv = ::select(fd + 1, &readfds, nullptr, nullptr, &tv);
        if (rv <= 0) {
            return false; // timeout or error
        }
        ssize_t n = ::recv(fd, &ch, 1, MSG_PEEK);
        if (n <= 0) {
            return false;
        }
        // Read one byte at a time to find newline
        n = ::recv(fd, &ch, 1, 0);
        if (n <= 0) return false;
        if (ch == '\n') {
            line = buf;
            return true;
        }
        if (ch != '\r') buf.push_back(ch);
        if (buf.size() > 4096) return false; // safety limit
    }
}

// Minimal base64 (no padding removal robustness beyond expected sizes)
std::string b64_encode(const unsigned char* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; out.reserve(((len+2)/3)*4);
    for (size_t i=0;i<len;i+=3){
        unsigned v = data[i]<<16 | ((i+1<len)?data[i+1]:0)<<8 | ((i+2<len)?data[i+2]:0);
        out.push_back(tbl[(v>>18)&0x3F]);
        out.push_back(tbl[(v>>12)&0x3F]);
        out.push_back((i+1<len)?tbl[(v>>6)&0x3F]:'=');
        out.push_back((i+2<len)?tbl[v&0x3F]:'=');
    }
    return out;
}
std::vector<unsigned char> b64_decode(const std::string &in) {
    static int lookup[256]; static bool init=false; if(!init){
        std::memset(lookup,-1,sizeof(lookup));
        const char* tbl="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for(int i=0;tbl[i];++i) lookup[(unsigned char)tbl[i]]=i; lookup[(unsigned char)'=']=0; init=true; }
    if(in.size()%4) return {};
    std::vector<unsigned char> out; out.reserve((in.size()/4)*3);
    for(size_t i=0;i<in.size(); i+=4){
        int c1=lookup[(unsigned char)in[i]]; int c2=lookup[(unsigned char)in[i+1]]; int c3=lookup[(unsigned char)in[i+2]]; int c4=lookup[(unsigned char)in[i+3]];
        if(c1<0||c2<0||c3<0||c4<0) return {};
        unsigned v = (c1<<18)|(c2<<12)|(c3<<6)|c4;
        out.push_back((v>>16)&0xFF);
        if(in[i+2] != '=') out.push_back((v>>8)&0xFF);
        if(in[i+3] != '=') out.push_back(v&0xFF);
    }
    return out;
}

#if HAVE_OPENSSL
bool derive_key_x25519(EVP_PKEY* my_key, const std::vector<unsigned char>& peer_pub, std::vector<unsigned char>& out_key) {
    EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), peer_pub.size());
    if(!peer_key){ return false; }
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(my_key, nullptr);
    if(!dctx){ EVP_PKEY_free(my_key); EVP_PKEY_free(peer_key); return false; }
    if(EVP_PKEY_derive_init(dctx)!=1){ EVP_PKEY_free(my_key); EVP_PKEY_free(peer_key); EVP_PKEY_CTX_free(dctx); return false; }
    if(EVP_PKEY_derive_set_peer(dctx, peer_key)!=1){ EVP_PKEY_free(my_key); EVP_PKEY_free(peer_key); EVP_PKEY_CTX_free(dctx); return false; }
    size_t secret_len=0; if(EVP_PKEY_derive(dctx,nullptr,&secret_len)!=1){ EVP_PKEY_free(my_key); EVP_PKEY_free(peer_key); EVP_PKEY_CTX_free(dctx); return false; }
    std::vector<unsigned char> secret(secret_len);
    if(EVP_PKEY_derive(dctx, secret.data(), &secret_len)!=1){ EVP_PKEY_free(my_key); EVP_PKEY_free(peer_key); EVP_PKEY_CTX_free(dctx); return false; }
    EVP_PKEY_CTX_free(dctx); EVP_PKEY_free(peer_key);
    // HKDF (simplified) using HMAC-SHA256: Extract with zero salt, expand with info="CNCHATv1"
    unsigned char salt[32] = {0};
    unsigned char prk[SHA256_DIGEST_LENGTH];
    // Extract
    {
        unsigned int len=0; unsigned char out[SHA256_DIGEST_LENGTH];
        HMAC(EVP_sha256(), salt, sizeof(salt), secret.data(), secret.size(), out, &len);
        std::memcpy(prk, out, len);
    }
    // Expand to 32 bytes
    const unsigned char info[] = {'C','N','C','H','A','T','v','1'};
    unsigned char t[SHA256_DIGEST_LENGTH]; unsigned int tlen=0; size_t out_len=32; out_key.resize(out_len);
    unsigned char round_input[sizeof(info)+1+SHA256_DIGEST_LENGTH];
    size_t round_input_len=0;
    // First block
    std::memcpy(round_input, info, sizeof(info)); round_input[sizeof(info)] = 0x01; round_input_len=sizeof(info)+1;
    HMAC(EVP_sha256(), prk, SHA256_DIGEST_LENGTH, round_input, round_input_len, t, &tlen);
    std::memcpy(out_key.data(), t, std::min((size_t)tlen,out_len));
    return true;
}
#endif

bool send_line(int fd, const std::string &s) {
    std::string out = s;
    if (out.empty() || out.back() != '\n') out.push_back('\n');
    return ::send(fd, out.c_str(), out.size(), 0) == (ssize_t)out.size();
}

} // namespace

bool perform_client_handshake(int fd, CryptoContext &ctx) {
#if HAVE_OPENSSL
    // Generate ephemeral X25519 key and send public.
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if(!pctx) return false;
    if(EVP_PKEY_keygen_init(pctx)!=1){ EVP_PKEY_CTX_free(pctx); return false; }
    EVP_PKEY *my_key=nullptr; if(EVP_PKEY_keygen(pctx,&my_key)!=1){ EVP_PKEY_CTX_free(pctx); return false; }
    EVP_PKEY_CTX_free(pctx);
    unsigned char pub_raw[32]; size_t pub_len=sizeof(pub_raw);
    if(EVP_PKEY_get_raw_public_key(my_key, pub_raw, &pub_len)!=1){ EVP_PKEY_free(my_key); return false; }
    std::string pub_b64 = b64_encode(pub_raw, pub_len);
    if(!send_line(fd, std::string("SEC-HELLO 1 ")+pub_b64)) { EVP_PKEY_free(my_key); return false; }
    std::string line; if(!recv_line_with_timeout(fd,line)) { EVP_PKEY_free(my_key); return false; }
    if(line.rfind("SEC-OK 1 ",0)!=0) { EVP_PKEY_free(my_key); return false; }
    std::string server_b64 = line.substr(std::string("SEC-OK 1 ").size());
    auto server_pub = b64_decode(server_b64);
    if(server_pub.size()!=32){ EVP_PKEY_free(my_key); return false; }
    std::vector<unsigned char> key_bytes; if(!derive_key_x25519(my_key, server_pub, key_bytes)){ EVP_PKEY_free(my_key); return false; }
    EVP_PKEY_free(my_key); ctx.set_symmetric_key(key_bytes); return true;
#else
    // Fallback: no encryption
    if(!send_line(fd, "SEC-HELLO 0")) return false; std::string line; if(!recv_line_with_timeout(fd,line)) return false; return false;
#endif
}

bool perform_server_handshake(int fd, CryptoContext &ctx) {
    std::string line; if(!recv_line_with_timeout(fd,line)) return false;
#if HAVE_OPENSSL
    if(line.rfind("SEC-HELLO 1 ",0)==0){
        std::string client_b64 = line.substr(std::string("SEC-HELLO 1 ").size());
        auto client_pub = b64_decode(client_b64);
        if(client_pub.size()!=32) return false;
        // Generate server key
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if(!pctx) return false; if(EVP_PKEY_keygen_init(pctx)!=1){ EVP_PKEY_CTX_free(pctx); return false; }
        EVP_PKEY *my_key=nullptr; if(EVP_PKEY_keygen(pctx,&my_key)!=1){ EVP_PKEY_CTX_free(pctx); return false; }
        EVP_PKEY_CTX_free(pctx);
        unsigned char pub_raw[32]; size_t pub_len=sizeof(pub_raw);
        if(EVP_PKEY_get_raw_public_key(my_key,pub_raw,&pub_len)!=1){ EVP_PKEY_free(my_key); return false; }
        std::string pub_b64 = b64_encode(pub_raw,pub_len);
        if(!send_line(fd, std::string("SEC-OK 1 ")+pub_b64)){ EVP_PKEY_free(my_key); return false; }
    std::vector<unsigned char> key_bytes; if(!derive_key_x25519(my_key, client_pub, key_bytes)){ EVP_PKEY_free(my_key); return false; }
    EVP_PKEY_free(my_key); ctx.set_symmetric_key(key_bytes); return true;
    }
    return false;
#else
    // Fallback: not encrypted
    if(line.rfind("SEC-HELLO",0)==0){ send_line(fd, "SEC-OK 0"); }
    return false;
#endif
}

} // namespace crypto
