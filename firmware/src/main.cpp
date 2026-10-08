// IoT IDPS node firmware (ESP32 / ESP8266).
//
// Responsibilities:
//   * publish HMAC-signed telemetry every IDPS_TELEMETRY_INTERVAL_MS
//   * accept HMAC-authenticated commands (PING / QUARANTINE / RELEASE)
//   * count what the backend needs to detect attacks on the node: MQTT
//     messages received, rejected commands, reconnects, free heap
//   * stay alive: non-blocking reconnects with backoff, watchdog, and a
//     last-resort reboot after a long outage
//
// The loop never blocks waiting for the network; the longest stall is one
// MQTT connect attempt (bounded by IDPS_MQTT_SOCKET_TIMEOUT_S).

#include <Arduino.h>
#include <PubSubClient.h>
#include <sys/time.h>
#include <time.h>

#if defined(ESP32)
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>
#elif defined(ESP8266)
#include <ESP8266WiFi.h>
#include <WiFiClientSecureBearSSL.h>
#endif

#include "commands.h"
#include "hmac_auth.h"
#include "idps_config.h"
#include "telemetry.h"
#include "util.h"

#if __has_include("secrets.h")
#include "secrets.h"
#else
#error "include/secrets.h is missing: copy include/secrets.example.h to include/secrets.h and fill it in"
#endif

#if IDPS_LOG_ENABLED
#define LOG(fmt, ...) Serial.printf("[%lu] " fmt "\n", static_cast<unsigned long>(millis()), ##__VA_ARGS__)
#else
#define LOG(...) \
  do {           \
  } while (0)
#endif

namespace {

#if IDPS_MQTT_USE_TLS
#if defined(ESP32)
WiFiClientSecure netClient;
#else
BearSSL::WiFiClientSecure netClient;
BearSSL::X509List caCert(IDPS_MQTT_CA_CERT);
#endif
#else
WiFiClient netClient;
#endif
PubSubClient mqtt(netClient);

char topicTelemetry[80];
char topicCommand[80];
char topicStatus[80];

uint8_t deviceKey[idps::kKeyLen];
bool keyUsable = false;

// Per-report-window counters; reset after each successful publish.
uint32_t windowRxMsgs = 0;
uint32_t windowAuthFail = 0;
// Cumulative since boot.
uint32_t wifiReconnects = 0;
uint32_t mqttReconnects = 0;

uint32_t bootId = 0;
uint32_t seq = 0;
uint64_t lastCmdTs = 0;
bool quarantined = false;
uint32_t quarantineSinceMs = 0;

bool wifiWasUp = false;
bool wifiEverUp = false;
bool mqttEverUp = false;
bool ntpStarted = false;
uint32_t lastWifiBeginMs = 0;
uint32_t lastMqttAttemptMs = 0;
uint32_t mqttBackoffMs = IDPS_MQTT_RETRY_MIN_MS;
uint32_t lastOnlineMs = 0;
uint32_t lastTelemetryMs = 0;

idps::RateLimiter commandLimiter(IDPS_CMD_RATE_PER_S);

uint32_t uptimeSeconds() {
#if defined(ESP32)
  return static_cast<uint32_t>(esp_timer_get_time() / 1000000LL);
#else
  return static_cast<uint32_t>(micros64() / 1000000ULL);
#endif
}

uint32_t hardwareRandom() {
#if defined(ESP32)
  return esp_random();
#else
  return ESP.random();
#endif
}

bool timeSynced() { return time(nullptr) > 1700000000; }

uint64_t nowUnixMs() {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return static_cast<uint64_t>(tv.tv_sec) * 1000ULL + static_cast<uint64_t>(tv.tv_usec / 1000);
}

bool validDeviceId(const char* id) {
  const size_t n = strlen(id);
  if (n == 0 || n > 32) return false;
  for (size_t i = 0; i < n; ++i) {
    const char c = id[i];
    if (!(isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-')) return false;
  }
  return true;
}

void setQuarantine(bool on) {
  quarantined = on;
  quarantineSinceMs = millis();
  digitalWrite(IDPS_SAFE_STATE_PIN, on ? IDPS_SAFE_STATE_ACTIVE_LEVEL : !IDPS_SAFE_STATE_ACTIVE_LEVEL);
  LOG("quarantine %s", on ? "ENABLED (outputs in safe state)" : "released");
}

// Runs inside mqtt.loop(). Must not publish: PubSubClient reuses its buffer.
void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  ++windowRxMsgs;
  if (strcmp(topic, topicCommand) != 0) return;
  if (!commandLimiter.admit(millis())) return;  // dropped unparsed under flood

  idps::CommandContext ctx{IDPS_DEVICE_ID, deviceKey, keyUsable, lastCmdTs, timeSynced(), nowUnixMs()};
  idps::Command cmd = idps::Command::kNone;
  uint64_t ts = 0;
  const idps::Verdict verdict = idps::verifyCommand(payload, length, ctx, &cmd, &ts);
  if (verdict != idps::Verdict::kAccepted) {
    ++windowAuthFail;
    LOG("command rejected: %s", idps::verdictName(verdict));
    return;
  }
  lastCmdTs = ts;
  switch (cmd) {
    case idps::Command::kPing: LOG("PING accepted"); break;
    case idps::Command::kQuarantine: setQuarantine(true); break;
    case idps::Command::kRelease: setQuarantine(false); break;
    case idps::Command::kNone: break;
  }
}

void maintainWifi(uint32_t now) {
  const bool up = WiFi.status() == WL_CONNECTED;
  if (up && !wifiWasUp) {
    if (wifiEverUp) ++wifiReconnects;
    wifiEverUp = true;
    LOG("Wi-Fi up, IP %s, RSSI %d", WiFi.localIP().toString().c_str(), static_cast<int>(WiFi.RSSI()));
    if (!ntpStarted) {
      configTime(0, 0, IDPS_NTP_SERVER_1, IDPS_NTP_SERVER_2);
      ntpStarted = true;
    }
  } else if (!up && wifiWasUp) {
    LOG("Wi-Fi lost");
  }
  if (!up && idps::elapsed(now, lastWifiBeginMs, IDPS_WIFI_RESTART_AFTER_MS)) {
    LOG("Wi-Fi still down, restarting association");
    WiFi.disconnect();
    WiFi.begin(IDPS_WIFI_SSID, IDPS_WIFI_PASSWORD);
    lastWifiBeginMs = now;
  }
  wifiWasUp = up;
}

void maintainMqtt(uint32_t now) {
  if (mqtt.connected()) {
    mqtt.loop();
    lastOnlineMs = now;
    return;
  }
  if (!wifiWasUp || !idps::elapsed(now, lastMqttAttemptMs, mqttBackoffMs)) return;
  lastMqttAttemptMs = now;

  const char* user = strlen(IDPS_MQTT_USERNAME) ? IDPS_MQTT_USERNAME : nullptr;
  const char* pass = strlen(IDPS_MQTT_PASSWORD) ? IDPS_MQTT_PASSWORD : nullptr;
  // Last will: the broker publishes "offline" (retained) if we vanish.
  if (mqtt.connect(IDPS_DEVICE_ID, user, pass, topicStatus, 1, true, "offline")) {
    if (mqttEverUp) ++mqttReconnects;
    mqttEverUp = true;
    mqttBackoffMs = IDPS_MQTT_RETRY_MIN_MS;
    mqtt.subscribe(topicCommand, 1);
    mqtt.publish(topicStatus, "online", true);
    lastOnlineMs = now;
    LOG("MQTT connected to %s:%d", IDPS_MQTT_HOST, IDPS_MQTT_PORT);
  } else {
    LOG("MQTT connect failed (state %d), retry in %lu ms", mqtt.state(), static_cast<unsigned long>(mqttBackoffMs));
    mqttBackoffMs = mqttBackoffMs >= IDPS_MQTT_RETRY_MAX_MS / 2 ? IDPS_MQTT_RETRY_MAX_MS : mqttBackoffMs * 2;
  }
}

void publishTelemetry(uint32_t now) {
  if (!mqtt.connected() || !idps::elapsed(now, lastTelemetryMs, IDPS_TELEMETRY_INTERVAL_MS)) return;
  lastTelemetryMs = now;
  ++seq;

  idps::TelemetryFields fields{};
  fields.bootId = bootId;
  fields.seq = seq;
  fields.uptimeS = uptimeSeconds();
  fields.rxMsgs = windowRxMsgs;
  fields.authFail = windowAuthFail;
  fields.freeHeap = static_cast<uint32_t>(ESP.getFreeHeap());
  fields.rssi = static_cast<int32_t>(WiFi.RSSI());
  fields.wifiReconnects = wifiReconnects;
  fields.mqttReconnects = mqttReconnects;
  fields.quarantined = quarantined;
  fields.lastCmdTs = lastCmdTs;
  char json[IDPS_MQTT_BUFFER_SIZE - 96];  // leave room for the MQTT header and topic
  if (idps::buildTelemetryJson(IDPS_DEVICE_ID, deviceKey, fields, json, sizeof(json)) < 0) return;

  if (mqtt.publish(topicTelemetry, json)) {
    windowRxMsgs = 0;
    windowAuthFail = 0;
  }
  // On failure the counters keep accumulating; the backend normalises by
  // the uptime delta, so rates stay correct.
}

void haltWithError(const char* message) {
  for (;;) {
    LOG("FATAL CONFIG ERROR: %s", message);
    delay(5000);  // feeds the ESP8266 watchdog; nothing else runs
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(50);
  pinMode(IDPS_SAFE_STATE_PIN, OUTPUT);
  digitalWrite(IDPS_SAFE_STATE_PIN, !IDPS_SAFE_STATE_ACTIVE_LEVEL);  // boot in normal (non-quarantined) state

  if (!validDeviceId(IDPS_DEVICE_ID)) haltWithError("IDPS_DEVICE_ID must be 1-32 chars of [A-Za-z0-9_-]");
  snprintf(topicTelemetry, sizeof(topicTelemetry), "%s/%s/telemetry", IDPS_TOPIC_PREFIX, IDPS_DEVICE_ID);
  snprintf(topicCommand, sizeof(topicCommand), "%s/%s/cmd", IDPS_TOPIC_PREFIX, IDPS_DEVICE_ID);
  snprintf(topicStatus, sizeof(topicStatus), "%s/%s/status", IDPS_TOPIC_PREFIX, IDPS_DEVICE_ID);

  const bool keyParsed = idps::fromHex(IDPS_DEVICE_KEY_HEX, deviceKey, idps::kKeyLen);
  bool keyNonZero = false;
  for (uint8_t b : deviceKey) keyNonZero |= (b != 0);
  const bool cryptoOk = idps::selfTest();
  keyUsable = keyParsed && keyNonZero && cryptoOk;
  LOG("device %s, HMAC self-test %s, key %s", IDPS_DEVICE_ID, cryptoOk ? "PASS" : "FAIL",
      keyUsable ? "ok" : "INVALID/PLACEHOLDER - commands disabled, telemetry unverifiable");

  WiFi.persistent(false);  // do not wear flash rewriting credentials on every boot
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(IDPS_WIFI_SSID, IDPS_WIFI_PASSWORD);
  lastWifiBeginMs = millis();
  bootId = hardwareRandom();  // after WiFi.begin(): RF on, hardware RNG fully seeded

#if IDPS_MQTT_USE_TLS
#if defined(ESP32)
  netClient.setCACert(IDPS_MQTT_CA_CERT);
#else
  netClient.setTrustAnchors(&caCert);
#endif
#endif
  mqtt.setServer(IDPS_MQTT_HOST, IDPS_MQTT_PORT);
  mqtt.setCallback(onMqttMessage);
  mqtt.setBufferSize(IDPS_MQTT_BUFFER_SIZE);
  mqtt.setSocketTimeout(IDPS_MQTT_SOCKET_TIMEOUT_S);
  mqtt.setKeepAlive(30);

#if defined(ESP32)
  // Reconfigure the task watchdog with a timeout above the worst-case
  // connect stall and subscribe the loop task to it.
  esp_task_wdt_init(IDPS_TASK_WDT_TIMEOUT_S, true);
  esp_task_wdt_add(nullptr);
#endif
  lastOnlineMs = millis();
  LOG("boot_id %lu, telemetry every %lu ms", static_cast<unsigned long>(bootId),
      static_cast<unsigned long>(IDPS_TELEMETRY_INTERVAL_MS));
}

void loop() {
#if defined(ESP32)
  esp_task_wdt_reset();
#endif
  const uint32_t now = millis();
  maintainWifi(now);
  maintainMqtt(now);
  publishTelemetry(now);

  if (quarantined && IDPS_QUARANTINE_AUTO_RELEASE_MS > 0 &&
      idps::elapsed(now, quarantineSinceMs, IDPS_QUARANTINE_AUTO_RELEASE_MS)) {
    LOG("quarantine auto-release timeout reached");
    setQuarantine(false);
  }
  if (idps::elapsed(now, lastOnlineMs, IDPS_REBOOT_AFTER_OFFLINE_MS)) {
    LOG("offline for too long, rebooting");
    delay(100);
    ESP.restart();
  }
  delay(10);  // yield to the Wi-Fi stack and let the CPU idle
}
