#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

namespace client {

using MessageHandler = std::function<void(const std::string &sender, const std::string &message)>;

class P2PListener {
public:
    P2PListener() = default;
    ~P2PListener();

    bool start(int port, MessageHandler handler);
    void stop();
    bool is_running() const noexcept { return running_.load(); }

private:
    void accept_loop();

    int listen_fd_{-1};
    std::thread worker_;
    std::atomic<bool> running_{false};
    MessageHandler handler_;
};

} // namespace client
