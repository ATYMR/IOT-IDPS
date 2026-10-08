# Security model

This document states what the system protects against, what it does not, and
what was wrong with the original prototype. It is deliberately conservative.

## Assets

* Integrity of device behaviour and of physical outputs driven by the node
* Integrity of the telemetry the IDPS bases decisions on
* The command channel to devices (it can change device state)
* Device keys and broker credentials

## Attacker model

| Attacker | Assumed capability |
|---|---|
| Network attacker on the LAN / Wi-Fi | Can sniff and inject Wi-Fi frames (deauth), connect to the broker if it allows anonymous or weakly authenticated clients, publish/subscribe to topics the broker permits |
| Malicious MQTT client | Holds *some* broker credentials; can flood, replay captured messages, forge payloads, reuse a client id |
| Physical attacker | **Out of scope**: can dump flash (keys are stored in plaintext in firmware; no flash encryption / secure boot configured) |
| Compromised backend host | **Out of scope**: holds all device keys |

## Controls

| Threat | Control | Status |
|---|---|---|
| Forged commands to a device | Per-device HMAC-SHA256 over device id + timestamp + command, constant-time compare | Implemented, host-tested |
| Replayed commands | Strictly increasing `ts` per boot + ±300 s window against NTP time; commands refused until time is synced (default) | Implemented; see residual risk 3 |
| Command flood / CPU exhaustion | Parse budget of 5 messages/s, 256-byte limit, no dynamic `String` | Implemented |
| Spoofed telemetry (to hide an attack or frame a device) | Per-device HMAC over every field; unauthenticated telemetry never updates state | Implemented |
| Replayed telemetry | `seq` monotonic per `boot_id`; retired `boot_id`s remembered | Implemented (in-memory) |
| Malformed / oversized payloads | Strict schema + range validation, 1 KiB limit, fuzz-style tests | Implemented |
| IDPS used as a weapon (tricked into quarantining healthy devices) | Only authenticated device-attributable findings can trigger quarantine; persistence + cooldown; auto-release; `detect` mode default | Implemented |
| Eavesdropping, credential theft on the wire | TLS (`IDPS_MQTT_USE_TLS`, `IDPS_MQTT_TLS`), CA-pinned on the device | Supported, **off by default**; compile-tested only |
| Unauthorised topic access | Broker auth + per-device ACLs | Example config in `deploy/mosquitto/`; must be deployed by the operator |
| Command injection via firewall responder | `ipaddress` validation, argv lists, no shell, refuses loopback/multicast/link-local, dry-run default | Implemented, experimental |
| Secrets in source control | `secrets.h` and `.env` git-ignored; CI fails if they are tracked | Implemented |
| Untrusted model files | joblib uses pickle → loading a model executes code. Only load models you trained | Documented |

## Residual risks (not solved)

1. **No confidentiality without TLS.** HMAC gives integrity, not secrecy.
   Telemetry is readable by anyone who can subscribe.
2. **Status/LWT topic is unauthenticated** (MQTT limitation); used for alerts only.
3. **Replay after reboot without NTP.** With `IDPS_REQUIRE_TIME_SYNC=0`, a
   captured command can be replayed after the device reboots, because the
   last accepted `ts` lives in RAM. Keep the default (`1`) or persist the
   counter in NVS/EEPROM.
4. **Backend state is in memory.** A backend restart forgets `seq`/`boot_id`
   history, opening a one-time replay window for previously captured telemetry.
5. **Symmetric keys.** Whoever holds the backend `.env` can impersonate every
   device. Key rotation is manual (re-flash + update `.env`).
6. **No flash encryption / secure boot.** Physical access reveals the key.
7. **A compromised device can lie.** The node reports its own counters; a
   device under full attacker control can send well-formed, correctly signed
   but false telemetry. The IDPS detects attacks *on* honest devices, and
   *some* symptoms of compromise (e.g. heap exhaustion), not a
   sophisticated compromised device.
8. **Quarantine is cooperative.** It only works if the device firmware is
   intact. It is a safety response, not containment of a compromised node.
9. **No broker-level prevention.** The IDPS cannot disconnect or ban MQTT
   clients; that requires broker integration (future work).
10. **The response can be induced.** In `prevent` mode, an attacker who can
    publish to a device's command topic can flood it with garbage. The device
    rejects every message, the IDPS sees a persistent `device_command_rejections`
    / anomaly, and it quarantines the device. That is a deliberate fail-safe
    trade-off: when a node is under attack, its outputs go to the safe state.
    It still means the attacker can force a safe-state outage (bounded by the
    15-min auto-release, then re-triggered while the flood continues). Mitigate
    with broker ACLs, so that only the backend can publish to `.../cmd`. Where
    availability matters more than fail-safe behaviour, use `detect` mode.
11. **Commands compete with a flood.** The device parses at most 5 command
    messages per second, so during a heavy flood the backend's legitimate
    QUARANTINE may be dropped unparsed. The backend retries every 30 s until
    the device confirms, but at very high flood rates delivery is unlikely.
    Again, broker ACLs are the real fix; a separate, ACL-protected control
    topic or a priority filter would be the next firmware step.

## Findings in the original prototype (fixed)

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | Critical | Device obeyed plaintext `DISCONNECT` / `QUARANTINE` from a **public** broker (`broker.hivemq.com`): anyone on the internet could disable it | HMAC-authenticated commands, private broker, replay protection |
| 2 | High | Wi-Fi SSID and password hardcoded in both sketches | Moved to git-ignored `secrets.h`; template provided. The sketches were never committed, but **rotate the Wi-Fi password if those files were ever shared** |
| 3 | High | `main.py` published `DISCONNECT` to the public broker as an import side effect | Removed; commands only via policy or explicit CLI |
| 4 | High | `ip_blocker` passed an unvalidated IP to `netsh` with `shell=True` (command injection if the IP ever came from input) | Validated IP, argv list, no shell, dry-run default |
| 5 | Medium | Telemetry unauthenticated; predictable client id on a public broker (trivial client-id takeover) | Signed telemetry; client id = device id on a private broker; takeover now shows up as `mqtt_reconnects` |
| 6 | Medium | `DISCONNECT` handler disconnected Wi-Fi and then spun in a reconnect loop with no Wi-Fi → node stuck until power cycle; blocking `while` loops could trip the ESP8266 watchdog | Removed command; non-blocking reconnect state machine with backoff, task watchdog, last-resort reboot |
| 7 | Low | `ip_blocker` slept inside the pipeline for the block duration | Expiry handled by `tick()`; nothing sleeps |
