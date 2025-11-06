#include "p2p_session_manager.hpp"
#include <iostream>

namespace client {

bool P2PSessionManager::ensure_session(const std::string &peer_username,
                                       const std::string &ip,
                                       int port,
                                       const std::string &local_username,
                                       bool &created) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(peer_username);
    if (it != sessions_.end()) {
        created = false;
        return it->second->ready();
    }
    auto session = std::make_shared<P2PSession>(peer_username, ip, port);
    if (!session->connect_and_handshake(local_username)) {
        return false;
    }
    sessions_[peer_username] = session;
    created = true;
    return true;
}

bool P2PSessionManager::send_message(const std::string &peer_username,
                                     const std::string &local_username,
                                     const std::string &message) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(peer_username);
    if (it == sessions_.end()) {
        return false;
    }
    std::string payload = local_username + " | " + message; // same format
    return it->second->send_plain(payload);
}

} // namespace client
