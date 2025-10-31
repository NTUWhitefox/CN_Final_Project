#include "command_handler.hpp"

#include <arpa/inet.h>
#include <cctype>
#include <sstream>

namespace server {

namespace {
bool is_valid_port_string(const std::string &port_str) {
    if (port_str.empty() || port_str.size() > 5) return false;
    for (unsigned char ch : port_str) {
        if (!std::isdigit(ch)) return false;
    }
    int value = std::stoi(port_str);
    return value >= 1024 && value <= 65535;
}

std::string ip_from_sockaddr(const sockaddr_in &addr) {
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, const_cast<in_addr *>(&addr.sin_addr), buf, sizeof(buf));
    return std::string(buf);
}
} // namespace

CommandResult CommandHandler::handle(int client_fd, const sockaddr_in &client_addr, const common::Command &cmd) {
    CommandResult result;

    auto prefix = [](const std::string &msg) {
        return std::string("[server] ") + msg;
    };

    switch (cmd.type) {
        case common::CommandType::Register: {
            if (cmd.args.size() != 2) {
                result.messages.push_back(prefix("ERROR usage: register <username> <password>"));
                break;
            }
            const std::string &username = cmd.args[0];
            const std::string &password = cmd.args[1];
            if (username.empty() || password.empty()) {
                result.messages.push_back(prefix("ERROR invalid username/password"));
                break;
            }
            std::string error;
            if (state_.register_user(username, password, error)) {
                result.messages.push_back(prefix("OK registered"));
            } else {
                result.messages.push_back(prefix("ERROR " + error));
            }
            break;
        }
        case common::CommandType::Login: {
            if (cmd.args.size() != 3) {
                result.messages.push_back(prefix("ERROR usage: login <username> <password> <port>"));
                break;
            }
            const std::string &username = cmd.args[0];
            const std::string &password = cmd.args[1];
            const std::string &port_str = cmd.args[2];
            if (!is_valid_port_string(port_str)) {
                result.messages.push_back(prefix("ERROR invalid port"));
                break;
            }
            int listen_port = std::stoi(port_str);
            std::string error;
            std::string ip = ip_from_sockaddr(client_addr);
            if (state_.login_user(client_fd, username, password, listen_port, ip, error)) {
                result.messages.push_back(prefix("OK welcome " + username));
            } else {
                result.messages.push_back(prefix("ERROR " + error));
            }
            break;
        }
        case common::CommandType::List: {
            auto session = state_.get_session(client_fd);
            if (!session || session->username.empty()) {
                result.messages.push_back(prefix("ERROR not logged in"));
                break;
            }
            auto online = state_.list_online_users();
            if (online.empty()) {
                result.messages.push_back(prefix("OK none online"));
                break;
            }
            result.messages.push_back(prefix("OK online:"));
            for (const auto &entry : online) {
                std::ostringstream oss;
                oss << entry.username;
                if (!entry.ip.empty() && entry.port != 0) {
                    oss << ' ' << entry.ip << ' ' << entry.port;
                }
                result.messages.push_back(prefix(oss.str()));
            }
            result.messages.push_back(prefix("."));
            break;
        }
        case common::CommandType::Logout: {
            std::string error;
            if (state_.logout_fd(client_fd, error)) {
                result.messages.push_back(prefix("OK bye"));
                result.close_after_send = true;
            } else {
                result.messages.push_back(prefix("ERROR " + error));
            }
            break;
        }
        case common::CommandType::SendTo: {
            auto session = state_.get_session(client_fd);
            if (!session || session->username.empty()) {
                result.messages.push_back(prefix("ERROR not logged in"));
                break;
            }
            if (cmd.args.empty()) {
                result.messages.push_back(prefix("ERROR usage: sendto <username> | <message>"));
                break;
            }
            const std::string &payload = cmd.args[0];
            auto pipe_pos = payload.find('|');
            if (pipe_pos == std::string::npos) {
                result.messages.push_back(prefix("ERROR usage: sendto <username> | <message>"));
                break;
            }
            auto trim = [](const std::string &s) {
                auto start = s.find_first_not_of(" \t\r\n");
                if (start == std::string::npos) return std::string();
                auto end = s.find_last_not_of(" \t\r\n");
                return s.substr(start, end - start + 1);
            };
            std::string target = trim(payload.substr(0, pipe_pos));
            std::string message = trim(payload.substr(pipe_pos + 1));
            if (target.empty() || message.empty()) {
                result.messages.push_back(prefix("ERROR usage: sendto <username> | <message>"));
                break;
            }
            if (target == session->username) {
                result.messages.push_back(prefix("ERROR sendto " + target + " cannot send to yourself"));
                break;
            }
            std::string ip;
            int port = 0;
            std::string error;
            if (!state_.get_peer_endpoint(target, ip, port, error)) {
                result.messages.push_back(prefix("ERROR sendto " + target + " " + error));
                break;
            }
            std::ostringstream oss;
            oss << "OK sendto " << target << ' ' << ip << ' ' << port;
            result.messages.push_back(prefix(oss.str()));
            break;
        }
        default:
            result.messages.push_back(prefix("ERROR unknown command"));
            break;
    }

    return result;
}

} // namespace server
