#include "p2p_listener.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

#include "../common/line_buffer.hpp"

namespace client {

namespace {
std::pair<std::string, std::string> parse_payload(const std::string &payload) {
    auto sep = payload.find('|');
    if (sep == std::string::npos) {
        return {"", payload};
    }
    auto trim = [](const std::string &s) {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return std::string();
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    };
    std::string sender = trim(payload.substr(0, sep));
    std::string message = trim(payload.substr(sep + 1));
    return {sender, message};
}
}

P2PListener::~P2PListener() {
    stop();
}

bool P2PListener::start(int port, MessageHandler handler) {
    stop();

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        perror("[client] p2p socket");
        return false;
    }

    int opt = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (::bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        perror("[client] p2p bind");
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    if (::listen(listen_fd_, 8) < 0) {
        perror("[client] p2p listen");
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    handler_ = std::move(handler);
    running_.store(true);
    worker_ = std::thread(&P2PListener::accept_loop, this);
    return true;
}

void P2PListener::stop() {
    if (!running_.load()) {
        return;
    }
    running_.store(false);
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (worker_.joinable()) {
        worker_.join();
    }
}

void P2PListener::accept_loop() {
    while (running_.load()) {
        sockaddr_in peer{};
        socklen_t len = sizeof(peer);
        int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr *>(&peer), &len);
        if (fd < 0) {
            if (running_.load()) {
                perror("[client] p2p accept");
            }
            continue;
        }

        common::LineBuffer buffer;
        char chunk[1024];
        ssize_t n = ::recv(fd, chunk, sizeof(chunk), 0);
        if (n > 0) {
            buffer.append(chunk, static_cast<std::size_t>(n));
            std::string line;
            while (buffer.pop_line(line)) {
                auto [sender, message] = parse_payload(line);
                if (handler_) {
                    handler_(sender, message);
                }
            }
        }
        ::close(fd);
    }
}

} // namespace client
