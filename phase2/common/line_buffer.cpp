#include "line_buffer.hpp"

namespace common {

void LineBuffer::append(const char *data, std::size_t length) {
    buffer_.append(data, length);
}

bool LineBuffer::pop_line(std::string &out_line) {
    auto pos = buffer_.find('\n');
    if (pos == std::string::npos) {
        return false;
    }
    out_line.assign(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(pos));
    buffer_.erase(0, pos + 1);
    if (!out_line.empty() && out_line.back() == '\r') {
        out_line.pop_back();
    }
    return true;
}

} // namespace common
