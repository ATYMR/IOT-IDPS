// Telemetry serialisation (pure function, also compiled by the host tests).
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace idps {

// Field order mirrors TELEMETRY_FIELDS in idps/protocol.py.
struct TelemetryFields {
  uint32_t bootId;
  uint32_t seq;
  uint32_t uptimeS;
  uint32_t rxMsgs;
  uint32_t authFail;
  uint32_t freeHeap;
  int32_t rssi;
  uint32_t wifiReconnects;
  uint32_t mqttReconnects;
  bool quarantined;
  uint64_t lastCmdTs;
};

// Builds the signed JSON payload. Returns its length, or -1 if it does not
// fit or HMAC fails.
int buildTelemetryJson(const char* deviceId, const uint8_t* key, const TelemetryFields& f, char* out, size_t outLen);

}  // namespace idps
