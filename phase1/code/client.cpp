#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
 #include <unistd.h>
#include <cstring>
#include <iostream>
 #include <cerrno>
 #include <string>
 #include <vector>
 #include <sstream>
 #include <algorithm>
 #include <cctype>

/* commands:
1. register <username> <password>
2. login <username> <password> <port_number>
3. list 
4. logout
*/

/*Notes
valid port number: 1024 - 65535
valid username: no space.
valid password: no space.
*/

static inline std::string trim(const std::string &s) {
	size_t start = s.find_first_not_of(" \t\r\n");
	if (start == std::string::npos) return "";
	size_t end = s.find_last_not_of(" \t\r\n");
	return s.substr(start, end - start + 1);
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port>\n";
		return 1;
	}
	const char* server_ip = argv[1];
	int server_port = std::stoi(argv[2]);

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) { perror("socket"); return 1; }

	sockaddr_in serv{};
	serv.sin_family = AF_INET;
	serv.sin_port = htons(server_port);
	if (inet_pton(AF_INET, server_ip, &serv.sin_addr) <= 0) {
		std::cerr << "Invalid server IP address\n";
		close(sockfd);
		return 1;
	}

	if (connect(sockfd, (sockaddr*)&serv, sizeof(serv)) < 0) {
		perror("connect");
		close(sockfd);
		return 1;
	}

	std::cout << "Connected to server " << server_ip << ":" << server_port << "\n";
	std::string inbuf;

	fd_set master, readfds;
	FD_ZERO(&master);
	FD_SET(sockfd, &master);
	FD_SET(STDIN_FILENO, &master);
	int fdmax = std::max(sockfd, STDIN_FILENO);

	while (true) {
		readfds = master;
		int ready = select(fdmax + 1, &readfds, nullptr, nullptr, nullptr);
		if (ready < 0) {
			if (errno == EINTR) continue;
			perror("select");
			break;
		}
		if (FD_ISSET(sockfd, &readfds)) {
			char buf[1024];
			ssize_t n = recv(sockfd, buf, sizeof(buf), 0);
			if (n <= 0) {
				if (n < 0) perror("recv");
				std::cout << "Server disconnected.\n";
				break;
			}
			std::cout.write(buf, n);
			std::cout.flush();
		}
		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			std::string line;
			if (!std::getline(std::cin, line)) {
				// EOF from stdin: exit
				break;
			}
			line = trim(line);
			if (line.empty()) continue;
			std::string sendline = line + "\n";
			ssize_t s = send(sockfd, sendline.c_str(), sendline.size(), 0);
			if (s < 0) { perror("send"); break; }
			// If user typed logout, we can expect server to close; we'll keep loop until recv says so
		}
	}

	close(sockfd);
	return 0;
}