#pragma once

#include <string>

namespace common {

class LineBuffer {
public:
    void append(const char *data, std::size_t length);
    bool pop_line(std::string &out_line);
    bool empty() const noexcept { return buffer_.empty(); }

private:
    std::string buffer_;
};

} // namespace common
