#include "server_app.hpp"

#include <arpa/inet.h>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/command.hpp"
#include "../common/line_buffer.hpp"
#include "../utils/crypto/handshake.hpp"
#include "../utils/crypto/crypto_context.hpp"

namespace server {

namespace {
constexpr int kBacklog = 32;
}

ServerApp::ServerApp(int port, std::size_t worker_count)
    : port_(port), pool_(worker_count), handler_(state_) {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        throw std::runtime_error("[server] Failed to create listening socket");
    }

    int opt = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (::bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        ::close(listen_fd_);
        throw std::runtime_error("[server] Failed to bind listening socket");
    }

    if (::listen(listen_fd_, kBacklog) < 0) {
        ::close(listen_fd_);
        throw std::runtime_error("[server] Failed to listen on port");
    }
}

ServerApp::~ServerApp() {
    stop();
}

void ServerApp::run() {
    running_.store(true);
    std::cout << "[server] Listening on port " << port_ << std::endl;
    accept_loop();
}

void ServerApp::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        pool_.shutdown();
    }
}

void ServerApp::accept_loop() {
    while (running_.load()) {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = ::accept(listen_fd_, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (!running_.load()) {
                break;
            }
            perror("accept");
            continue;
        }

        pool_.enqueue([this, client_fd, client_addr]() mutable {
            try {
                handle_client(client_fd, client_addr);
            } catch (const std::exception &ex) {
                std::cerr << "[server] Exception handling client: " << ex.what() << std::endl;
            }
        });
    }
}

void ServerApp::handle_client(int client_fd, sockaddr_in client_addr) {
    state_.add_session(client_fd, client_addr);
    crypto::CryptoContext crypto_ctx;
    bool handshake_ok = crypto::perform_server_handshake(client_fd, crypto_ctx);
    send_line(client_fd, "[server] Welcome to the CN chat server (phase 2 scaffold).");

    common::LineBuffer buffer;
    char chunk[1024];

    while (true) {
        ssize_t n = ::recv(client_fd, chunk, sizeof(chunk), 0);
        if (n <= 0) {
            if (n < 0) {
                perror("recv");
            }
            break;
        }
        buffer.append(chunk, static_cast<std::size_t>(n));
        std::string line;
        while (buffer.pop_line(line)) {
            // Decrypt if needed
            if (crypto_ctx.ready()) {
                if (line.rfind("ENC ", 0) == 0) {
                    std::string enc = line.substr(4);
                    std::string plain;
                    if (!crypto_ctx.decrypt(enc, plain)) {
                        send_line(client_fd, "[server] ERROR decrypt");
                        continue;
                    }
                    line = plain;
                } else {
                    // If encryption is negotiated, ignore non-ENC lines (except early handshake/compat)
                }
            }
            auto cmd = common::parse_command_line(line);
            auto result = handler_.handle(client_fd, client_addr, cmd);
            for (const auto &msg : result.messages) {
                if (crypto_ctx.ready()) {
                    std::string enc;
                    if (crypto_ctx.encrypt(msg, enc)) {
                        send_line(client_fd, std::string("ENC ") + enc);
                    } else {
                        send_line(client_fd, msg);
                    }
                } else {
                    send_line(client_fd, msg);
                }
            }
            if (result.close_after_send) {
                ::shutdown(client_fd, SHUT_RDWR);
                ::close(client_fd);
                state_.remove_session(client_fd);
                return;
            }
        }
    }

    ::close(client_fd);
    state_.remove_session(client_fd);
}

void ServerApp::send_line(int client_fd, const std::string &message) {
    std::string out = message;
    if (out.empty() || out.back() != '\n') {
        out.push_back('\n');
    }
    ::send(client_fd, out.c_str(), out.size(), 0);
}

} // namespace server
