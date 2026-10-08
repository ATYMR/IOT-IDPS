#include "hmac_auth.h"

#include <string.h>

#include "idps_config.h"
#include "protocol_vectors.h"

#if defined(ESP32)
#include "mbedtls/md.h"
#elif defined(ESP8266)
#include <bearssl/bearssl.h>
#elif defined(IDPS_HOST_TEST)
// Host unit tests link a reference implementation (firmware/test/host/sha256_ref.cpp).
bool hostHmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[32]);
#else
#error "unsupported platform"
#endif

namespace idps {

bool hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[kMacLen]) {
#if defined(ESP32)
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info != nullptr && mbedtls_md_hmac(info, key, keyLen, msg, msgLen, out) == 0;
#elif defined(IDPS_HOST_TEST)
  return hostHmacSha256(key, keyLen, msg, msgLen, out);
#else
  br_hmac_key_context kc;
  br_hmac_context ctx;
  br_hmac_key_init(&kc, &br_sha256_vtable, key, keyLen);
  br_hmac_init(&ctx, &kc, 0);
  br_hmac_update(&ctx, msg, msgLen);
  br_hmac_out(&ctx, out);
  return true;
#endif
}

void toHex(const uint8_t* data, size_t len, char* out) {
  static const char kDigits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[2 * i] = kDigits[data[i] >> 4];
    out[2 * i + 1] = kDigits[data[i] & 0x0f];
  }
  out[2 * len] = '\0';
}

static int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool fromHex(const char* hex, uint8_t* out, size_t outLen) {
  if (hex == nullptr || strlen(hex) != 2 * outLen) return false;
  for (size_t i = 0; i < outLen; ++i) {
    int hi = hexNibble(hex[2 * i]);
    int lo = hexNibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

bool macEqualsHex(const uint8_t mac[kMacLen], const char* hex, size_t hexLen) {
  if (hex == nullptr || hexLen != 2 * kMacLen) return false;
  char expected[2 * kMacLen + 1];
  toHex(mac, kMacLen, expected);
  uint8_t diff = 0;
  for (size_t i = 0; i < 2 * kMacLen; ++i) {
    char c = hex[i];
    if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    diff |= static_cast<uint8_t>(expected[i] ^ c);
  }
  return diff == 0;
}

bool selfTest() {
  uint8_t key[kKeyLen];
  for (size_t i = 0; i < kKeyLen; ++i) key[i] = static_cast<uint8_t>(i);
  uint8_t mac[kMacLen];
  const char* msg = IDPS_KAT_MESSAGE;
  if (!hmacSha256(key, kKeyLen, reinterpret_cast<const uint8_t*>(msg), strlen(msg), mac)) return false;
  return macEqualsHex(mac, IDPS_KAT_MAC_HEX, strlen(IDPS_KAT_MAC_HEX));
}

}  // namespace idps
