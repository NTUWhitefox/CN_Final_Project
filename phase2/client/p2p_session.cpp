#include "p2p_session.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>

namespace client {

P2PSession::P2PSession(const std::string &peer_username,
                       const std::string &peer_ip,
                       int peer_port)
    : peer_username_(peer_username), peer_ip_(peer_ip), peer_port_(peer_port) {}

P2PSession::~P2PSession() {
    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        fd_ = -1;
    }
}

bool P2PSession::connect_and_handshake(const std::string &local_username) {
    if (ready_.load()) return true; // already established
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) {
        perror("[client] p2p session socket");
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer_port_);
    if (::inet_pton(AF_INET, peer_ip_.c_str(), &addr.sin_addr) <= 0) {
        ::close(fd_); fd_ = -1; return false;
    }
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("[client] p2p session connect");
        ::close(fd_); fd_ = -1; return false;
    }
    if (!crypto::perform_client_handshake(fd_, ctx_)) {
        std::cerr << "[client] p2p handshake failed with peer " << peer_username_ << std::endl;
        ::close(fd_); fd_ = -1; return false;
    }
    // Send IDENT line encrypted
    std::string ident = "IDENT " + local_username;
    std::string enc;
    if (ctx_.encrypt(ident, enc)) {
        std::string frame = "ENC " + enc + '\n';
        ::send(fd_, frame.c_str(), frame.size(), 0);
    }
    ready_.store(true);
    return true;
}

bool P2PSession::send_plain(const std::string &plain) {
    if (fd_ < 0) return false;
    std::lock_guard<std::mutex> lock(send_mutex_);
    std::string payload = plain;
    if (ctx_.ready()) {
        std::string enc;
        if (ctx_.encrypt(payload, enc)) {
            payload = std::string("ENC ") + enc;
        }
    }
    if (payload.empty() || payload.back() != '\n') payload.push_back('\n');
    ssize_t n = ::send(fd_, payload.c_str(), payload.size(), 0);
    return n == (ssize_t)payload.size();
}

} // namespace client
