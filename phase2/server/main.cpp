#include "server_app.hpp"

#include <cstdlib>
#include <iostream>

int main(int argc, char *argv[]) {
    int port = 8080;
    if (argc >= 2) {
        port = std::atoi(argv[1]);
        if (port <= 0) {
            std::cerr << "[server] Invalid port provided, defaulting to 8080" << std::endl;
            port = 8080;
        }
    }

    try {
        server::ServerApp app(port);
        app.run();
    } catch (const std::exception &ex) {
        std::cerr << "[server] Fatal error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
