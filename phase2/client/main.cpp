#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <ctime>

#include "../common/line_buffer.hpp"
#include "p2p_listener.hpp"
#include "p2p_sender.hpp"
#include "p2p_session_manager.hpp"
#include "../utils/crypto/handshake.hpp"
#include "../utils/crypto/crypto_context.hpp"

namespace {

std::string trim(const std::string &s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return std::string();
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

void print_line(const std::string &line) {
    static std::mutex cout_mutex;
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << line << std::endl;
}

std::string current_time_string() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%H:%M:%S");
    return oss.str();
}

} // namespace

struct PendingSend {
    std::string target;
    std::string message;
};

struct ClientState {
    std::mutex mutex;
    bool logged_in{false};
    std::string username;
    int listen_port{0};
    int pending_login_port{0};
    std::deque<PendingSend> pending_sends;
    client::P2PListener listener;
    crypto::CryptoContext crypto_ctx;
    client::P2PSessionManager p2p_sessions;
};

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port>" << std::endl;
        return 1;
    }

    const char *server_ip = argv[1];
    int server_port = std::atoi(argv[2]);
    if (server_port <= 0 || server_port > 65535) {
        std::cerr << "Invalid server port" << std::endl;
        return 1;
    }

    int sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (::inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid server IP address" << std::endl;
        ::close(sockfd);
        return 1;
    }

    if (::connect(sockfd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) < 0) {
        perror("connect");
        ::close(sockfd);
        return 1;
    }

    print_line("[client] Connected to server " + std::string(server_ip) + ":" + std::to_string(server_port));

    std::atomic<bool> running{true};
    ClientState state;

    if (crypto::perform_client_handshake(sockfd, state.crypto_ctx)) {
        print_line("[client] Secure channel established.");
    } else {
        print_line("[client] Proceeding without encryption (handshake skipped).");
    }

    auto handle_incoming_message = [&](const std::string &sender, const std::string &message) {
        std::string display_sender = sender.empty() ? "unknown" : sender;
        std::string display_message = message;
        auto timestamp = current_time_string();
        print_line("[(" + timestamp + ") " + display_sender + " : " + display_message + "]");
    };

    std::thread reader([&]() {
        common::LineBuffer buffer;
        char chunk[1024];
        while (running.load()) {
            ssize_t n = ::recv(sockfd, chunk, sizeof(chunk), 0);
            if (n <= 0) {
                if (n < 0) {
                    perror("recv");
                }
                running.store(false);
                break;
            }
            buffer.append(chunk, static_cast<std::size_t>(n));
            std::string line;
            while (buffer.pop_line(line)) {
                // Decrypt if server sent encrypted line
                {
                    std::lock_guard<std::mutex> lock(state.mutex);
                    if (state.crypto_ctx.ready() && line.rfind("ENC ", 0) == 0) {
                        std::string enc = line.substr(4);
                        std::string plain;
                        if (state.crypto_ctx.decrypt(enc, plain)) {
                            line = plain;
                        } else {
                            print_line("[client] ERROR: failed to decrypt server message");
                            continue;
                        }
                    }
                }
                if (line.rfind("[server] OK welcome ", 0) == 0) {
                    std::istringstream iss(line.substr(std::string("[server] OK welcome ").size()));
                    std::string username;
                    iss >> username;
                    if (!username.empty()) {
                        std::lock_guard<std::mutex> lock(state.mutex);
                        state.username = username;
                        state.logged_in = true;
                        int port = state.pending_login_port;
                        state.listen_port = port;
                        state.pending_login_port = 0;
                        if (port > 0) {
                            if (!state.listener.start(port, handle_incoming_message)) {
                                print_line("[client] Failed to start P2P listener on port " + std::to_string(port));
                            } else {
                                print_line("[client] P2P listener started on port " + std::to_string(port));
                            }
                        }
                    }
                } else if (line.rfind("[server] OK bye", 0) == 0) {
                    std::lock_guard<std::mutex> lock(state.mutex);
                    state.logged_in = false;
                    state.username.clear();
                    state.listen_port = 0;
                    state.pending_login_port = 0;
                    state.pending_sends.clear();
                    state.listener.stop();
                } else if (line.rfind("[server] OK sendto ", 0) == 0) {
                    fprintf(stderr, "Processing sendto response: %s\n", line.c_str());
                    std::istringstream iss(line.substr(std::string("[server] OK sendto ").size()));
                    std::string target;
                    std::string ip;
                    int port = 0;
                    iss >> target >> ip >> port;
                    if (target.empty() || ip.empty() || port == 0) {
                        print_line("[client] Invalid sendto response from server.");
                    } else {
                        PendingSend pending;
                        bool found = false;
                        {
                            std::lock_guard<std::mutex> lock(state.mutex);
                            for (auto it = state.pending_sends.begin(); it != state.pending_sends.end(); ++it) {
                                if (it->target == target) {
                                    pending = *it;
                                    state.pending_sends.erase(it);
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (!found) {
                            print_line("[client] No pending message for user '" + target + "'.");
                        } else {
                            // Avoid holding state.mutex during network operations
                            std::string sender;
                            client::P2PSessionManager* mgr = nullptr;
                            {
                                std::lock_guard<std::mutex> lock(state.mutex);
                                sender = state.username;
                                mgr = &state.p2p_sessions;
                            }
                            bool created = false;
                            bool ok = false;
                            if (mgr) {
                                ok = mgr->ensure_session(target, ip, port, sender, created);
                                if (ok) {
                                    ok = mgr->send_message(target, sender, pending.message);
                                }
                            }
                            if (!ok) {
                                print_line("[client] Failed to deliver message to '" + target + "'.");
                            } else {
                                if (created) {
                                    print_line("[client] New secure P2P session with '" + target + "' established.");
                                }
                                print_line("[client] Message delivered to '" + target + "'.");
                            }
                        }
                    }
                    fprintf(stderr, "Finished processing sendto response.\n");
                } else if (line.rfind("[server] ERROR sendto ", 0) == 0) {
                    std::istringstream iss(line.substr(std::string("[server] ERROR sendto ").size()));
                    std::string target;
                    iss >> target;
                    if (!target.empty()) {
                        std::lock_guard<std::mutex> lock(state.mutex);
                        for (auto it = state.pending_sends.begin(); it != state.pending_sends.end(); ++it) {
                            if (it->target == target) {
                                state.pending_sends.erase(it);
                                break;
                            }
                        }
                    }
                }
                print_line(line);
            }
        }
    });

    std::thread writer([&]() {
        std::string line;
        while (running.load()) {
            if (!std::getline(std::cin, line)) {
                running.store(false);
                break;
            }
            std::string trimmed = trim(line);
            if (trimmed.empty()) continue;

            std::string lower = trimmed;
            for (auto &ch : lower) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

            auto keyword_end = lower.find(' ');
            std::string keyword = keyword_end == std::string::npos ? lower : lower.substr(0, keyword_end);

            if (keyword == "login") {
                std::istringstream iss(trimmed);
                std::string cmd, user, pass, port_str;
                if (!(iss >> cmd >> user >> pass >> port_str)) {
                    print_line("[client] usage: login <username> <password> <port>");
                    continue;
                }
                int port = std::atoi(port_str.c_str());
                if (port < 1024 || port > 65535) {
                    print_line("[client] Invalid listening port (1024-65535).");
                    continue;
                }
                {
                    std::lock_guard<std::mutex> lock(state.mutex);
                    state.pending_login_port = port;
                }
            } else if (keyword == "sendto") {
                auto remainder_pos = trimmed.find(' ');
                if (remainder_pos == std::string::npos) {
                    print_line("[client] usage: sendto <username> | <message>");
                    continue;
                }
                std::string remainder = trim(trimmed.substr(remainder_pos + 1));
                auto pipe_pos = remainder.find('|');
                if (pipe_pos == std::string::npos) {
                    print_line("[client] usage: sendto <username> | <message>");
                    continue;
                }
                std::string target = trim(remainder.substr(0, pipe_pos));
                std::string message = trim(remainder.substr(pipe_pos + 1));
                if (target.empty() || message.empty()) {
                    print_line("[client] usage: sendto <username> | <message>");
                    continue;
                }
                bool logged_in = false;
                {
                    std::lock_guard<std::mutex> lock(state.mutex);
                    logged_in = state.logged_in;
                }
                if (!logged_in) {
                    print_line("[client] You must login before sending messages.");
                    continue;
                }
                {
                    std::lock_guard<std::mutex> lock(state.mutex);
                    state.pending_sends.push_back(PendingSend{target, message});
                }
            }

            std::string to_send;
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                if (state.crypto_ctx.ready()) {
                    std::string enc;
                    if (state.crypto_ctx.encrypt(trimmed, enc)) {
                        to_send = std::string("ENC ") + enc + '\n';
                    } else {
                        to_send = trimmed + '\n';
                    }
                } else {
                    to_send = trimmed + '\n';
                }
            }
            fprintf(stderr, "Try send to server: %s", to_send.c_str());
            ssize_t sent = ::send(sockfd, to_send.c_str(), to_send.size(), 0);
            fprintf(stderr, "Sent to server: %s", to_send.c_str());
            if (sent < 0) {
                perror("send");
                running.store(false);
                break;
            }
            // If the user requested logout, we proactively stop writer loop to allow clean shutdown.
            if (keyword == "logout") {
                // Wait briefly for reader to process server's bye.
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                break;
            }
        }
    });

    writer.join();
    running.store(false);
    ::shutdown(sockfd, SHUT_RDWR);
    reader.join();
    ::close(sockfd);

    {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.listener.stop();
    }

    print_line("[client] Exiting.");
    return 0;
}
