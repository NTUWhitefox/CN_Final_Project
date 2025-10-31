#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <cerrno>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <utils/user.hpp>

//functionalities:
//1. user registration
//2. user login
//5. logging out
//6. list online users

namespace {
constexpr int DEFAULT_PORT = 8080;

static inline std::string trim(const std::string &s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static inline std::vector<std::string> split_ws(const std::string &s) {
    std::istringstream iss(s);
    std::vector<std::string> parts;
    std::string tok;
    while (iss >> tok) parts.push_back(tok);
    return parts;
}

bool is_valid_port(const std::string &pstr) {
    if (pstr.empty() || pstr.size() > 5) return false;
    for (char c : pstr) if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    int p = std::stoi(pstr);
    return p >= 1024 && p <= 65535;
}

std::string sockaddr_to_ip(const sockaddr_in &addr) {
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, (void*)&addr.sin_addr, buf, sizeof(buf));
    return std::string(buf);
}
}

int main(int argc, char* argv[]) {
    int port = DEFAULT_PORT;
    if (argc >= 2) {
        // optional custom port
        try {
            port = std::stoi(argv[1]);
        } catch (...) {
            std::cerr << "Invalid port argument, using default " << DEFAULT_PORT << "\n";
            port = DEFAULT_PORT;
        }
    }

    int server_fd;
    int opt = 1;
    struct sockaddr_in servaddr{};

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, 16) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    std::cout << "Server listening on port " << port << std::endl;

    // User database and sessions
    std::unordered_map<std::string, User> users; // registered users by username
    std::unordered_map<int, std::string> sessions; // fd -> username (logged in)
    std::unordered_map<int, std::string> recv_buf; // fd -> buffer for partial lines
    std::unordered_map<int, sockaddr_in> peer_addr; // fd -> peer address

    fd_set master_set, read_fds;
    FD_ZERO(&master_set);
    FD_SET(server_fd, &master_set);
    int fdmax = server_fd;

    auto send_line = [](int fd, const std::string &msg) {
        std::string out = msg;
        if (out.empty() || out.back() != '\n') out.push_back('\n');
        ssize_t n = send(fd, out.c_str(), out.size(), 0);
        (void)n;
    };

    // Returns true if logout was successful and socket should be closed
    auto handle_command = [&](int fd, const std::string &line) -> bool {
        std::string t = trim(line);
        if (t.empty()) return false;
        auto parts = split_ws(t);
        if (parts.empty()) return false;
        std::string cmd = parts[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

        if (cmd == "register") {
            if (parts.size() != 3) { send_line(fd, "ERROR usage: register <username> <password>"); return false; }
            const std::string &u = parts[1];
            const std::string &p = parts[2];
            if (u.find(' ') != std::string::npos || p.find(' ') != std::string::npos || u.empty() || p.empty()) {
                send_line(fd, "ERROR invalid username/password"); return false;
            }
            if (users.find(u) != users.end()) { send_line(fd, "ERROR username exists"); return false; }
            User usr; usr.username = u; usr.password = p; usr.userId = static_cast<int>(users.size()) + 1; usr.portNumber = 0; usr.ip = "";
            users[u] = usr;
            send_line(fd, "OK registered");
            return false;
        } else if (cmd == "login") {
            if (parts.size() != 4) { send_line(fd, "ERROR usage: login <username> <password> <port>"); return false; }
            const std::string &u = parts[1];
            const std::string &p = parts[2];
            const std::string &pstr = parts[3];
            if (!is_valid_port(pstr)) { send_line(fd, "ERROR invalid port"); return false; }
            int cport = std::stoi(pstr);

            auto it = users.find(u);
            if (it == users.end()) { send_line(fd, "ERROR no such user"); return false; }
            if (it->second.password != p) { send_line(fd, "ERROR wrong password"); return false; }
            // duplicate login check
            bool already_online = false;
            for (const auto &kv : sessions) { if (kv.second == u) { already_online = true; break; } }
            if (already_online) { send_line(fd, "ERROR already logged in"); return false; }

            // get client IP
            std::string client_ip = "";
            auto pa = peer_addr.find(fd);
            if (pa != peer_addr.end()) {
                client_ip = sockaddr_to_ip(pa->second);
            }
            // check for duplicate (IP, port) among online users
            for (const auto &kv : sessions) {
                const std::string &other_user = kv.second;
                if (other_user == u) continue; // skip self
                const auto &other = users[other_user];
                if (!other.ip.empty() && other.portNumber != 0) {
                    if (other.ip == client_ip && other.portNumber == cport) {
                        send_line(fd, "ERROR port in use on this IP");
                        return false;
                    }
                }
            }

            // record session
            sessions[fd] = u;
            it->second.portNumber = cport;
            it->second.ip = client_ip;
            send_line(fd, "OK welcome " + u);
            return false;
        } else if (cmd == "list") {
            if (sessions.find(fd) == sessions.end()) { send_line(fd, "ERROR not logged in"); return false; }
            std::vector<std::string> lines;
            for (const auto &kv : sessions) {
                const std::string &uname = kv.second;
                const auto &u = users[uname];
                std::ostringstream oss;
                oss << uname;
                if (!u.ip.empty() && u.portNumber != 0) {
                    oss << " " << u.ip << " " << u.portNumber;
                }
                lines.push_back(oss.str());
            }
            if (lines.empty()) { send_line(fd, "OK none online"); }
            else {
                send_line(fd, "OK online:");
                for (auto &l : lines) send_line(fd, l);
                send_line(fd, ".");
            }
            return false;
        } else if (cmd == "logout") {
            auto it = sessions.find(fd);
            if (it == sessions.end()) {
                send_line(fd, "ERROR not logged in");
                return false;
            }
            std::string uname = it->second;
            sessions.erase(it);
            send_line(fd, "OK bye");
            return true;
        } else {
            send_line(fd, "ERROR unknown command");
            return false;
        }
    };

    while (true) {
        read_fds = master_set;
        int ready = select(fdmax + 1, &read_fds, nullptr, nullptr, nullptr);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        for (int fd = 0; fd <= fdmax && ready > 0; ++fd) {
            if (!FD_ISSET(fd, &read_fds)) continue;
            --ready;
            if (fd == server_fd) {
                // accept new client
                sockaddr_in cliaddr{}; socklen_t clen = sizeof(cliaddr);
                int cfd = accept(server_fd, (sockaddr*)&cliaddr, &clen);
                if (cfd < 0) { perror("accept"); continue; }
                FD_SET(cfd, &master_set);
                if (cfd > fdmax) fdmax = cfd;
                recv_buf[cfd] = "";
                peer_addr[cfd] = cliaddr;
                // greet
                std::string greet = "Welcome. Commands: register, login, list, logout";
                send(cfd, (greet + "\n").c_str(), greet.size() + 1, 0);
            } else {
                // receive data from client
                char buf[1024];
                ssize_t n = recv(fd, buf, sizeof(buf), 0);
                if (n <= 0) {
                    // disconnect or error
                    if (n < 0) perror("recv");
                    // cleanup session if logged in
                    auto sit = sessions.find(fd);
                    if (sit != sessions.end()) {
                        sessions.erase(sit);
                    }
                    close(fd);
                    FD_CLR(fd, &master_set);
                    recv_buf.erase(fd);
                    peer_addr.erase(fd);
                    continue;
                }
                // append and process lines
                std::string &acc = recv_buf[fd];
                acc.append(buf, buf + n);
                size_t pos;
                bool want_close = false;
                while ((pos = acc.find('\n')) != std::string::npos) {
                    std::string line = acc.substr(0, pos);
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    bool did_logout = handle_command(fd, line);
                    if (did_logout) {
                        want_close = true;
                    }
                    acc.erase(0, pos + 1);
                }
                if (want_close) {
                    close(fd);
                    FD_CLR(fd, &master_set);
                    recv_buf.erase(fd);
                    peer_addr.erase(fd);
                }
            }
        }
    }

    // Cleanup
    for (int fd = 0; fd <= fdmax; ++fd) {
        if (FD_ISSET(fd, &master_set)) close(fd);
    }
    return 0;
}