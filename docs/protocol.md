# Wire protocol v1

Implemented in `idps/protocol.py` (backend) and `firmware/src/{telemetry,commands}.cpp`
(device). Compatibility is enforced by `tests/test_firmware_consistency.py`
(static) and `tests/test_firmware_host.py` (the firmware code compiled for the
host and driven with backend-generated payloads).

## Topics

| Topic | Direction | QoS | Retained | Authenticated |
|---|---|---|---|---|
| `idps/v1/{device_id}/telemetry` | device → backend | 0 | no | yes (HMAC) |
| `idps/v1/{device_id}/status` | device/broker → backend | 0 (`online`), 1 (last will) | yes | **no** (MQTT last will) |
| `idps/v1/{device_id}/cmd` | backend → device | 1 | no | yes (HMAC) |

`device_id` must match `^[A-Za-z0-9_-]{1,32}$`. The prefix is configurable
(backend: `IDPS_TOPIC_PREFIX` env var; firmware: `IDPS_TOPIC_PREFIX` in `idps_config.h`).

## Keys

One 32-byte key per device, shared between that device (`secrets.h`) and the
backend (`IDPS_DEVICE_KEYS`). Generate with `python -m idps gen-key`. All-zero
keys are rejected on both sides.

## Telemetry

Published every 5 s:

```json
{"v":1,"device_id":"esp32_01","boot_id":3735928559,"seq":42,"uptime_s":215,
 "rx_msgs":0,"auth_fail":0,"free_heap":210344,"rssi":-61,
 "wifi_reconnects":0,"mqtt_reconnects":1,"quarantined":0,
 "last_cmd_ts":0,"mac":"<64 lowercase hex>"}
```

| Field | Type / range | Meaning |
|---|---|---|
| `boot_id` | uint32 | Hardware-random value chosen at boot; distinguishes reboots from replays |
| `seq` | uint32 | Increments per publish attempt since boot |
| `uptime_s` | uint32 | Seconds since boot (64-bit timer, no `millis()` wrap) |
| `rx_msgs` | uint32 | MQTT messages received since the last successful publish |
| `auth_fail` | uint32 | Commands rejected (malformed, bad MAC, replayed, stale) since the last publish |
| `free_heap` | uint32 | `ESP.getFreeHeap()` bytes |
| `rssi` | int, −127…0 | Wi-Fi RSSI in dBm |
| `wifi_reconnects`, `mqtt_reconnects` | uint32 | Cumulative since boot |
| `quarantined` | 0/1 | Safe-state active |
| `last_cmd_ts` | uint64 | Timestamp of the last accepted command (ms) |

MAC = `HMAC-SHA256(key, canonical)` where `canonical` is the ASCII string

```
v1|telemetry|<device_id>|<boot_id>|<seq>|<uptime_s>|<rx_msgs>|<auth_fail>|<free_heap>|<rssi>|<wifi_reconnects>|<mqtt_reconnects>|<quarantined>|<last_cmd_ts>
```

Integers in decimal, no padding. Using a canonical string instead of the JSON
bytes avoids JSON canonicalisation problems; the `telemetry` tag gives domain
separation from commands.

Backend validation (`decode_telemetry`): ≤ 1024 bytes, UTF-8 JSON object,
`v == 1`, `device_id` matches the topic, every field present, integer (not
bool), in range; then MAC; then replay checks (`seq` must increase within a
`boot_id`; a previously retired `boot_id` is a replay).

## Commands

```json
{"ts":1733000000123,"cmd":"QUARANTINE","mac":"<64 hex>"}
```

`cmd` ∈ `PING`, `QUARANTINE`, `RELEASE`. MAC over
`v1|cmd|<device_id>|<ts>|<cmd>`. `ts` is Unix time in milliseconds; the
backend keeps it strictly increasing.

Device checks, in order (first failure wins; every failure increments `auth_fail`):

1. rate limit: at most 5 command messages parsed per second; the rest are
   dropped *without* parsing (counted in `rx_msgs` only)
2. length ≤ 256 bytes
3. JSON object with integer `ts` ≥ 0, string `cmd`, string `mac`
4. known command
5. node has a usable key and passed its HMAC self-test
6. MAC matches (constant-time compare)
7. `ts` > last accepted `ts` (replay)
8. if NTP time is known: `|ts − now| ≤ 300 s`; if not and
   `IDPS_REQUIRE_TIME_SYNC=1` (default): reject

Known-answer vector (checked at boot and by the test suite):

```
key     = 00 01 02 … 1f
message = v1|cmd|esp32_01|1700000000000|PING
mac     = ef976d0a669bcf5bb8cd32d10ca0a0570cb7b3aaea6f1a89a02d129ddfa7efa1
```

## Status / last will

On connect the node sets an MQTT last will of `offline` (retained) on its
status topic and publishes `online` (retained). This is **not** authenticated:
anyone allowed to publish on that topic can fake it, so the backend only uses
it to raise a low-to-medium `device_offline` alert, never to act.
