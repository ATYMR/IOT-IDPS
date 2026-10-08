// Copy to secrets.h (git-ignored) and fill in. NEVER commit secrets.h.
//
//   cp include/secrets.example.h include/secrets.h
//   python -m idps gen-key --device-id esp32_01   # prints the key lines below
#pragma once

#define IDPS_WIFI_SSID "your-wifi-ssid"
#define IDPS_WIFI_PASSWORD "your-wifi-password"

#define IDPS_MQTT_HOST "192.168.1.10"   // your own broker; avoid public test brokers
#define IDPS_MQTT_PORT 1883              // 8883 when IDPS_MQTT_USE_TLS=1
#define IDPS_MQTT_USERNAME ""            // empty = anonymous (not recommended)
#define IDPS_MQTT_PASSWORD ""

// Unique per device. Must also appear in the backend's IDPS_DEVICE_KEYS.
#define IDPS_DEVICE_ID "esp32_01"
// 32-byte HMAC-SHA256 key, 64 hex chars. The all-zero placeholder is
// rejected at boot: the node then refuses every command.
#define IDPS_DEVICE_KEY_HEX "0000000000000000000000000000000000000000000000000000000000000000"

// TLS (optional). Build with -DIDPS_MQTT_USE_TLS=1 and paste your broker's
// CA certificate (PEM). TLS certificate validation needs NTP time.
#ifndef IDPS_MQTT_USE_TLS
#define IDPS_MQTT_USE_TLS 0
#endif
static const char IDPS_MQTT_CA_CERT[] = R"PEM(
-----BEGIN CERTIFICATE-----
...paste your CA certificate here...
-----END CERTIFICATE-----
)PEM";
