#pragma once

// Toggle OpenSSL usage at compile time. The Makefile can pass -DHAVE_OPENSSL=1
// when libssl-dev is installed. Default to 0 (disabled) to keep builds working
// even if OpenSSL headers are missing.
#ifndef HAVE_OPENSSL
#define HAVE_OPENSSL 0
#endif
