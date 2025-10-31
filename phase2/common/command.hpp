#pragma once

#include <string>
#include <vector>

namespace common {

enum class CommandType {
    Register,
    Login,
    List,
    Logout,
    SendTo,
    SendToGroup,
    Unknown
};

struct Command {
    CommandType type{CommandType::Unknown};
    std::vector<std::string> args; // split tokens after command keyword
    std::string raw;               // original line for reference
};

Command parse_command_line(const std::string &line);
std::string command_type_to_string(CommandType type);

} // namespace common
