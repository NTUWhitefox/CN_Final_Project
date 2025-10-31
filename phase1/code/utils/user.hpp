#include <string>

// Simple user record for in-memory storage on server
struct User {
    std::string username;
    std::string password;
    int userId = 0;
    int portNumber = 0;
    std::string ip; // set on login from peer address
};