#include "command.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace common {

namespace {
CommandType keyword_to_type(const std::string &keyword) {
    std::string lower = keyword;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (lower == "register") return CommandType::Register;
    if (lower == "login") return CommandType::Login;
    if (lower == "list") return CommandType::List;
    if (lower == "logout") return CommandType::Logout;
    if (lower == "sendto") return CommandType::SendTo;
    if (lower == "sendtogroup") return CommandType::SendToGroup;
    return CommandType::Unknown;
}
} // namespace

Command parse_command_line(const std::string &line) {
    Command cmd;
    cmd.raw = line;
    std::istringstream iss(line);
    std::string keyword;
    if (!(iss >> keyword)) {
        cmd.type = CommandType::Unknown;
        return cmd;
    }
    cmd.type = keyword_to_type(keyword);
    std::string remainder;
    std::getline(iss, remainder);
    if (!remainder.empty()) {
        // strip leading whitespace from remainder before tokenising
        auto first_non_ws = remainder.find_first_not_of(" \t");
        if (first_non_ws != std::string::npos) {
            remainder = remainder.substr(first_non_ws);
        } else {
            remainder.clear();
        }
    }
    if (!remainder.empty()) {
        std::istringstream arg_stream(remainder);
        std::string token;
        while (arg_stream >> token) {
            cmd.args.emplace_back(token);
        }
        if (cmd.type == CommandType::SendTo || cmd.type == CommandType::SendToGroup) {
            // Preserve the portion after the first token group for custom parsing later
            cmd.args.clear();
            cmd.args.push_back(remainder);
        }
    }
    return cmd;
}

std::string command_type_to_string(CommandType type) {
    switch (type) {
        case CommandType::Register: return "register";
        case CommandType::Login: return "login";
        case CommandType::List: return "list";
        case CommandType::Logout: return "logout";
        case CommandType::SendTo: return "sendto";
        case CommandType::SendToGroup: return "sendtogroup";
        case CommandType::Unknown:
        default: return "unknown";
    }
}

} // namespace common
