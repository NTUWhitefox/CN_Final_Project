#pragma once

#include <string>
#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

#include "../utils/crypto/crypto_context.hpp"
#include "../utils/crypto/handshake.hpp"
#include "../common/line_buffer.hpp"

namespace client {

class P2PSession {
public:
    P2PSession(const std::string &peer_username,
               const std::string &peer_ip,
               int peer_port);
    ~P2PSession();

    bool connect_and_handshake(const std::string &local_username);
    bool ready() const noexcept { return ready_.load(); }
    const std::string &peer_username() const { return peer_username_; }

    bool send_plain(const std::string &plain); // encrypts if ready
private:
    int fd_{-1};
    std::string peer_username_;
    std::string peer_ip_;
    int peer_port_;
    std::atomic<bool> ready_{false};
    crypto::CryptoContext ctx_;
    std::mutex send_mutex_;
};

} // namespace client
