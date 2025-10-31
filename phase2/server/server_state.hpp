#pragma once

#include <netinet/in.h>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "../utils/user.hpp"

namespace server {

struct SessionInfo {
    int fd{-1};
    sockaddr_in address{};
    std::string username; // empty until logged in
};

struct OnlineUserInfo {
    std::string username;
    std::string ip;
    int port{0};
};

class ServerState {
public:
    void add_session(int fd, const sockaddr_in &addr);
    void remove_session(int fd);

    bool has_session(int fd) const;
    std::optional<SessionInfo> get_session(int fd) const;

    bool register_user(const std::string &username,
                        const std::string &password,
                        std::string &error_msg);

    bool login_user(int fd,
                    const std::string &username,
                    const std::string &password,
                    int listen_port,
                    const std::string &ip,
                    std::string &error_msg);

    bool logout_fd(int fd, std::string &error_msg);

    std::vector<OnlineUserInfo> list_online_users() const;

    bool get_peer_endpoint(const std::string &username,
                           std::string &ip,
                           int &port,
                           std::string &error_msg) const;

private:
    bool is_port_in_use_locked(const std::string &ip, int port, const std::string &exclude_username) const;

    mutable std::mutex mutex_;
    std::unordered_map<int, SessionInfo> sessions_;           // fd -> session
    std::unordered_map<std::string, User> users_;             // username -> record
    std::unordered_map<std::string, int> username_to_fd_;     // username -> fd (online)
};

} // namespace server
