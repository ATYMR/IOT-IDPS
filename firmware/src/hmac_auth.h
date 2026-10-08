// HMAC-SHA256 helpers built on the platform crypto library
// (mbedTLS on ESP32, BearSSL on ESP8266).
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace idps {

constexpr size_t kKeyLen = 32;
constexpr size_t kMacLen = 32;

bool hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[kMacLen]);

// Writes 2*len hex chars plus a NUL terminator into out (size >= 2*len+1).
void toHex(const uint8_t* data, size_t len, char* out);

// Parses exactly 2*outLen hex chars. Returns false on bad length/characters.
bool fromHex(const char* hex, uint8_t* out, size_t outLen);

// Compares a computed MAC with a received hex string without early exit.
bool macEqualsHex(const uint8_t mac[kMacLen], const char* hex, size_t hexLen);

// Known-answer test against include/protocol_vectors.h.
bool selfTest();

}  // namespace idps
