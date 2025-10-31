#include "server_state.hpp"

#include <arpa/inet.h>

namespace server {

namespace {
std::string sockaddr_to_ip(const sockaddr_in &addr) {
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, const_cast<in_addr *>(&addr.sin_addr), buf, sizeof(buf));
    return std::string(buf);
}
}

void ServerState::add_session(int fd, const sockaddr_in &addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    SessionInfo info;
    info.fd = fd;
    info.address = addr;
    sessions_[fd] = info;
}

void ServerState::remove_session(int fd) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto sit = sessions_.find(fd);
    if (sit != sessions_.end()) {
        if (!sit->second.username.empty()) {
            auto uit = users_.find(sit->second.username);
            if (uit != users_.end()) {
                uit->second.logged_in = false;
                uit->second.portNumber = 0;
                uit->second.ip.clear();
            }
            username_to_fd_.erase(sit->second.username);
        }
        sessions_.erase(sit);
    }
}

bool ServerState::has_session(int fd) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.find(fd) != sessions_.end();
}

std::optional<SessionInfo> ServerState::get_session(int fd) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(fd);
    if (it == sessions_.end()) return std::nullopt;
    return it->second;
}

bool ServerState::register_user(const std::string &username,
                                const std::string &password,
                                std::string &error_msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (username.empty() || password.empty()) {
        error_msg = "invalid username/password";
        return false;
    }
    if (users_.find(username) != users_.end()) {
        error_msg = "username exists";
        return false;
    }
    User user;
    user.username = username;
    user.password = password;
    user.userId = static_cast<int>(users_.size()) + 1;
    users_[username] = user;
    return true;
}

bool ServerState::login_user(int fd,
                             const std::string &username,
                             const std::string &password,
                             int listen_port,
                             const std::string &ip,
                             std::string &error_msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto sit = sessions_.find(fd);
    if (sit == sessions_.end()) {
        error_msg = "session not found";
        return false;
    }
    auto uit = users_.find(username);
    if (uit == users_.end()) {
        error_msg = "no such user";
        return false;
    }
    User &user = uit->second;
    if (user.password != password) {
        error_msg = "wrong password";
        return false;
    }
    if (user.logged_in) {
        error_msg = "already logged in";
        return false;
    }
    if (is_port_in_use_locked(ip, listen_port, username)) {
        error_msg = "port in use on this IP";
        return false;
    }

    user.logged_in = true;
    user.portNumber = listen_port;
    user.ip = ip;
    sit->second.username = username;
    username_to_fd_[username] = fd;
    return true;
}

bool ServerState::logout_fd(int fd, std::string &error_msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto sit = sessions_.find(fd);
    if (sit == sessions_.end()) {
        error_msg = "session not found";
        return false;
    }
    if (sit->second.username.empty()) {
        error_msg = "not logged in";
        return false;
    }
    auto uit = users_.find(sit->second.username);
    if (uit != users_.end()) {
        uit->second.logged_in = false;
        uit->second.portNumber = 0;
        uit->second.ip.clear();
    }
    username_to_fd_.erase(sit->second.username);
    sit->second.username.clear();
    return true;
}

std::vector<OnlineUserInfo> ServerState::list_online_users() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<OnlineUserInfo> result;
    result.reserve(username_to_fd_.size());
    for (const auto &entry : username_to_fd_) {
        const auto &username = entry.first;
        auto uit = users_.find(username);
        if (uit == users_.end()) continue;
        const User &user = uit->second;
        if (!user.logged_in) continue;
        result.push_back(OnlineUserInfo{username, user.ip, user.portNumber});
    }
    return result;
}

bool ServerState::is_port_in_use_locked(const std::string &ip, int port, const std::string &exclude_username) const {
    for (const auto &pair : users_) {
        const User &user = pair.second;
        if (!user.logged_in) continue;
        if (user.username == exclude_username) continue;
        if (user.ip == ip && user.portNumber == port) {
            return true;
        }
    }
    return false;
}

bool ServerState::get_peer_endpoint(const std::string &username,
                                    std::string &ip,
                                    int &port,
                                    std::string &error_msg) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto uit = users_.find(username);
    if (uit == users_.end()) {
        error_msg = "no such user";
        return false;
    }
    const User &user = uit->second;
    if (!user.logged_in) {
        error_msg = "user not online";
        return false;
    }
    if (user.ip.empty() || user.portNumber == 0) {
        error_msg = "user has no endpoint";
        return false;
    }
    ip = user.ip;
    port = user.portNumber;
    return true;
}

} // namespace server
