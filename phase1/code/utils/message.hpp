#include <string>
#include <ctime>

struct Message {
    int id;
    std::string content;
    std::time_t timestamp;
};