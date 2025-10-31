#include "p2p_sender.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace client {

bool send_p2p_message(const std::string &ip,
                      int port,
                      const std::string &sender,
                      const std::string &message,
                      std::string &error) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        error = "socket";
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        error = "invalid address";
        ::close(fd);
        return false;
    }

    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        error = std::strerror(errno);
        ::close(fd);
        return false;
    }

    std::string payload = sender + " | " + message + '\n';
    ssize_t n = ::send(fd, payload.c_str(), payload.size(), 0);
    if (n < 0) {
        error = std::strerror(errno);
        ::close(fd);
        return false;
    }

    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
    return true;
}

} // namespace client
