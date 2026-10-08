#pragma once

#include <stddef.h>
#include <stdint.h>

namespace idps {

// Decimal formatting for uint64_t (newlib-nano printf on ESP8266 lacks %llu).
// `out` must hold at least 21 bytes.
inline void formatU64(uint64_t value, char* out) {
  char tmp[21];
  size_t n = 0;
  do {
    tmp[n++] = static_cast<char>('0' + value % 10);
    value /= 10;
  } while (value != 0);
  for (size_t i = 0; i < n; ++i) out[i] = tmp[n - 1 - i];
  out[n] = '\0';
}

// Wrap-safe "has `interval` elapsed since `since`" for millis() timestamps.
inline bool elapsed(uint32_t now, uint32_t since, uint32_t interval) {
  return static_cast<uint32_t>(now - since) >= interval;
}

}  // namespace idps
