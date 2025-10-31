#pragma once

#include <atomic>
#include <netinet/in.h>

#include "server_state.hpp"
#include "thread_pool.hpp"
#include "command_handler.hpp"

namespace server {

class ServerApp {
public:
    ServerApp(int port, std::size_t worker_count = 10);
    ~ServerApp();

    void run();
    void stop();

private:
    void accept_loop();
    void handle_client(int client_fd, sockaddr_in client_addr);
    void send_line(int client_fd, const std::string &message);

    int port_;
    int listen_fd_{-1};
    std::atomic<bool> running_{false};

    ThreadPool pool_;
    ServerState state_;
    CommandHandler handler_;
};

} // namespace server
