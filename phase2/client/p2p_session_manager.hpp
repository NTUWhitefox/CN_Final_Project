#pragma once

#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>

#include "p2p_session.hpp"

namespace client {

class P2PSessionManager {
public:
    bool ensure_session(const std::string &peer_username,
                        const std::string &ip,
                        int port,
                        const std::string &local_username,
                        bool &created);

    bool send_message(const std::string &peer_username,
                      const std::string &local_username,
                      const std::string &message);

private:
    std::unordered_map<std::string, std::shared_ptr<P2PSession>> sessions_;
    std::mutex mutex_;
};

} // namespace client
