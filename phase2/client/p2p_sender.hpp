#pragma once

#include <string>

namespace client {

bool send_p2p_message(const std::string &ip,
                      int port,
                      const std::string &sender,
                      const std::string &message,
                      std::string &error);

} // namespace client
