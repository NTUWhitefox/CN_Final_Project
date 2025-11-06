#pragma once

#include <string>
#include "crypto_context.hpp"

namespace crypto {

// Client side: send hello and await OK; on success, sets a temporary symmetric key.
bool perform_client_handshake(int fd, CryptoContext &ctx);

// Server side: await hello and reply OK; on success, sets a temporary symmetric key.
bool perform_server_handshake(int fd, CryptoContext &ctx);

} // namespace crypto
