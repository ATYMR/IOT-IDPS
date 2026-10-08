# Hardware, flashing and on-device validation

## Supported boards

| Board | PlatformIO env | Notes |
|---|---|---|
| ESP32 DevKit (ESP32-WROOM-32) | `esp32dev` | Arduino-ESP32 core 2.0.17 (platform `espressif32@6.9.0`) |
| NodeMCU v1.0 (ESP-12E, ESP8266) | `nodemcuv2` | ESP8266 Arduino core 3.1.2 (platform `espressif8266@4.2.1`) |

Both boards run the same firmware. USB-UART drivers: CP210x or CH340,
depending on the board.

The **safe-state pin** defaults to GPIO2 (the on-board LED on both boards).
In a real deployment, connect it to whatever must fail safe (relay, valve,
motor-driver enable). Its active level is in `firmware/include/idps_config.h`.

## Flashing

```bash
cd firmware
cp include/secrets.example.h include/secrets.h      # then edit it
python -m idps gen-key --device-id esp32_01          # paste the key into secrets.h and .env
pio run -e esp32dev -t upload                        # or -e nodemcuv2
pio device monitor -b 115200
```

Expected boot log (illustrative: assembled from the log statements in `main.cpp`, not captured from a device):

```
[53] device esp32_01, HMAC self-test PASS, key ok
[55] boot_id 2930120471, telemetry every 5000 ms
[2310] Wi-Fi up, IP 192.168.1.42, RSSI -58
[2391] MQTT connected to 192.168.1.10:1883
```

If the log says `key INVALID/PLACEHOLDER`, the node still publishes telemetry,
but the backend rejects it, and the node refuses every command.

## Build footprint (measured, plain MQTT / TLS)

| Board | RAM (static) | Flash |
|---|---|---|
| ESP32 | 45.5 KB / 320 KB (13.9 %) | 776 KB / 1.25 MB (59.2 %) → TLS 910 KB (69.4 %) |
| ESP8266 | 30.4 KB / 80 KB (37.2 %) | 295 KB / 1 MB (28.2 %) → TLS 399 KB (38.2 %) |

Static RAM does not include the TLS handshake. BearSSL on the ESP8266 needs
roughly 20-30 KB of free heap at runtime, which is tight. Verify on hardware.

## Validation that REQUIRES hardware (not yet done)

Everything below was **not** validated in this repository. The firmware was
compiled for both boards, and its command/telemetry logic was compiled and
tested on a PC. It has not run on a physical board as part of this work.

| # | Check | How |
|---|---|---|
| H1 | Boot self-test passes on both chips (mbedTLS / BearSSL HMAC) | Serial log shows `HMAC self-test PASS` |
| H2 | Telemetry accepted by the backend | `python -m idps listen` shows no `telemetry_auth_failure` |
| H3 | Commands work end-to-end | `python -m idps send-command esp32_01 QUARANTINE` → LED changes, telemetry `quarantined=1`; `RELEASE` reverts |
| H4 | Replay rejected | Re-publish a captured command with `mosquitto_pub` → serial `command rejected: replay` |
| H5 | Flood resilience | `for i in $(seq 1000); do mosquitto_pub -t idps/v1/esp32_01/cmd -m x; done` → node stays responsive, `rx_msgs`/`auth_fail` rise, backend alerts |
| H6 | Wi-Fi loss recovery | Power-cycle the AP → node reconnects with backoff, `wifi_reconnects` increments |
| H7 | Broker loss recovery | Stop the broker > 10 min → node reboots once (last-resort path), then recovers |
| H8 | Client-id takeover visible | Connect another client with the device's id → `mqtt_reconnects` rises, alert |
| H9 | Watchdog | Temporarily add a `while(1){}` → ESP32 task watchdog resets after 30 s |
| H10 | TLS | Build with `-DIDPS_MQTT_USE_TLS=1` against `deploy/mosquitto` → connects on 8883; check free heap on ESP8266 |
| H11 | Long run | 7-day soak test: watch `free_heap` trend, reconnect counters, uptime (no unexpected `boot_id` changes) |
| H12 | Auto-release | Quarantine, wait 15 min → released |
