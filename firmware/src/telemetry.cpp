#include "telemetry.h"

#include <stdio.h>

#include "hmac_auth.h"
#include "idps_config.h"
#include "util.h"

namespace idps {

int buildTelemetryJson(const char* deviceId, const uint8_t* key, const TelemetryFields& f, char* out, size_t outLen) {
  int32_t rssi = f.rssi;
  if (rssi > 0) rssi = 0;  // some cores report positive values when unknown
  if (rssi < -127) rssi = -127;
  char lastCmd[21];
  formatU64(f.lastCmdTs, lastCmd);

  // Canonical string for the MAC: "v1|telemetry|<device>|<fields...>".
  char canonical[256];
  int n = snprintf(canonical, sizeof(canonical), "v%d|telemetry|%s|%lu|%lu|%lu|%lu|%lu|%lu|%ld|%lu|%lu|%u|%s",
                   IDPS_PROTOCOL_VERSION, deviceId, static_cast<unsigned long>(f.bootId),
                   static_cast<unsigned long>(f.seq), static_cast<unsigned long>(f.uptimeS),
                   static_cast<unsigned long>(f.rxMsgs), static_cast<unsigned long>(f.authFail),
                   static_cast<unsigned long>(f.freeHeap), static_cast<long>(rssi),
                   static_cast<unsigned long>(f.wifiReconnects), static_cast<unsigned long>(f.mqttReconnects),
                   f.quarantined ? 1u : 0u, lastCmd);
  if (n <= 0 || static_cast<size_t>(n) >= sizeof(canonical)) return -1;

  uint8_t mac[kMacLen];
  if (!hmacSha256(key, kKeyLen, reinterpret_cast<const uint8_t*>(canonical), static_cast<size_t>(n), mac)) return -1;
  char macHex[2 * kMacLen + 1];
  toHex(mac, kMacLen, macHex);

  n = snprintf(out, outLen,
               "{\"v\":%d,\"device_id\":\"%s\",\"boot_id\":%lu,\"seq\":%lu,\"uptime_s\":%lu,\"rx_msgs\":%lu,"
               "\"auth_fail\":%lu,\"free_heap\":%lu,\"rssi\":%ld,\"wifi_reconnects\":%lu,\"mqtt_reconnects\":%lu,"
               "\"quarantined\":%u,\"last_cmd_ts\":%s,\"mac\":\"%s\"}",
               IDPS_PROTOCOL_VERSION, deviceId, static_cast<unsigned long>(f.bootId),
               static_cast<unsigned long>(f.seq), static_cast<unsigned long>(f.uptimeS),
               static_cast<unsigned long>(f.rxMsgs), static_cast<unsigned long>(f.authFail),
               static_cast<unsigned long>(f.freeHeap), static_cast<long>(rssi),
               static_cast<unsigned long>(f.wifiReconnects), static_cast<unsigned long>(f.mqttReconnects),
               f.quarantined ? 1u : 0u, lastCmd, macHex);
  if (n <= 0 || static_cast<size_t>(n) >= outLen) return -1;
  return n;
}

}  // namespace idps
