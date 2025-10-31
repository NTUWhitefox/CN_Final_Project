#pragma once

#include <string>
#include <vector>
#include <netinet/in.h>

#include "../common/command.hpp"
#include "server_state.hpp"

namespace server {

struct CommandResult {
    std::vector<std::string> messages;
    bool close_after_send{false};
};

class CommandHandler {
public:
    explicit CommandHandler(ServerState &state) : state_(state) {}
    CommandResult handle(int client_fd, const sockaddr_in &client_addr, const common::Command &cmd);

private:
    ServerState &state_;
};

} // namespace server
