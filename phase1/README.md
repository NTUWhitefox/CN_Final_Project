# CN Project Phase 1 - Simple Chat Server/Client

Minimal server and client in C++ (Linux sockets) to support:
- register \<username> \<password>
- login \<username> \<password> \<port_number>
- list
- logout

No user-to-user chat yet (next phase). No threading; server uses select() to handle multiple clients concurrently.

## Build (WSL/Linux)

```bash
make -C code
```

Artifacts:
- `code/bin/server`
- `code/bin/client`

## Run

- Start server (optional custom port, default 8080):
```bash
./code/bin/server            # default 8080
# or
./code/bin/server 9000
```

- Start two clients (connect to server IP and port):
```bash
 8080
./code/bin/client 127.0.0.1 8080
```

## Protocol

- register <username> <password>
  - Errors: username exists, invalid username/password
- login <username> <password> <port>
  - On success server stores client's IP and provided port
  - Errors: no such user, wrong password, already logged in, invalid port
- list
  - Requires login; returns list of online users (username ip port). Ends with a line containing a single `.`
- logout
  - Logs out and the server closes the connection.

Server responds with lines prefixed with `OK` or `ERROR`.

## Notes
- Valid port range: 1024-65535
- Username/password cannot contain spaces.
- Basic error handling for unknown commands, duplicate registration/login, invalid port numbers.
- If a client disconnects unexpectedly, the server cleans up their session.
