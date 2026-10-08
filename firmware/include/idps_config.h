// Non-secret firmware tunables. Secrets live in secrets.h (git-ignored).
//
// Values marked [protocol] must match idps/protocol.py; this is checked by
// tests/test_firmware_consistency.py.
#pragma once

#define IDPS_PROTOCOL_VERSION 1                  // [protocol]
#define IDPS_TOPIC_PREFIX "idps/v1"              // [protocol]
#define IDPS_HMAC_HEX_LEN 64                     // [protocol] SHA-256 -> 64 hex chars
#define IDPS_MAX_CMD_PAYLOAD 256                 // longer command payloads are rejected unparsed
#define IDPS_MQTT_BUFFER_SIZE 512                // PubSubClient packet buffer (telemetry ~300 B)

#define IDPS_TELEMETRY_INTERVAL_MS 5000UL        // must match IDPS_TELEMETRY_INTERVAL_S on the backend

// Command handling
#define IDPS_CMD_RATE_PER_S 5                    // command messages parsed per second; extra are dropped
#define IDPS_CMD_MAX_SKEW_S 300                  // reject commands whose timestamp is further off than this
#define IDPS_REQUIRE_TIME_SYNC 1                 // 1 = refuse commands until NTP time is known (replay safety)
#define IDPS_NTP_SERVER_1 "pool.ntp.org"
#define IDPS_NTP_SERVER_2 "time.nist.gov"

// Quarantine: drive IDPS_SAFE_STATE_PIN to its safe level. In a real
// deployment this pin would gate an actuator (relay, valve, motor driver).
// 0 disables auto-release; otherwise quarantine ends after this long so a
// false positive cannot disable a device forever.
#define IDPS_QUARANTINE_AUTO_RELEASE_MS (15UL * 60UL * 1000UL)
#ifndef IDPS_SAFE_STATE_PIN
#define IDPS_SAFE_STATE_PIN 2                    // on-board LED on ESP32 DevKit and ESP-12 (NodeMCU)
#endif
#if defined(ESP8266)
#define IDPS_SAFE_STATE_ACTIVE_LEVEL LOW         // NodeMCU on-board LED is active-low
#else
#define IDPS_SAFE_STATE_ACTIVE_LEVEL HIGH
#endif

// Connectivity / recovery
#define IDPS_WIFI_RESTART_AFTER_MS 30000UL       // re-issue WiFi.begin() if still down after this
#define IDPS_MQTT_RETRY_MIN_MS 2000UL            // exponential backoff for MQTT reconnects
#define IDPS_MQTT_RETRY_MAX_MS 60000UL
#define IDPS_MQTT_SOCKET_TIMEOUT_S 5
#define IDPS_REBOOT_AFTER_OFFLINE_MS (10UL * 60UL * 1000UL)  // last-resort recovery
#define IDPS_TASK_WDT_TIMEOUT_S 30               // ESP32 loop-task watchdog

#ifndef IDPS_LOG_ENABLED
#define IDPS_LOG_ENABLED 1
#endif
