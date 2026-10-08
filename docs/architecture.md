# Architecture

## 1. System overview

```mermaid
flowchart LR
    subgraph Devices["ESP32 / ESP8266 nodes (firmware/)"]
        FW["Firmware<br/>counters + HMAC signer<br/>command verifier"]
        PIN["Safe-state GPIO<br/>(LED / relay)"]
        FW --> PIN
    end

    subgraph Broker["MQTT broker (Mosquitto)"]
        T["idps/v1/{id}/telemetry"]
        S["idps/v1/{id}/status (LWT)"]
        C["idps/v1/{id}/cmd"]
    end

    subgraph Backend["Python backend (idps/)"]
        RT["mqtt_runtime<br/>listener"]
        EN["engine<br/>validate → features → detect"]
        RK["risk + policy"]
        RS["response<br/>alerts / commands / firewall"]
        RT --> EN --> RK --> RS
    end

    FW -- "signed telemetry (5 s)" --> T
    FW -. "last will" .-> S
    T --> RT
    S --> RT
    RS -- "signed QUARANTINE / RELEASE / PING" --> C
    C --> FW
    RS --> LOG[("logs/alerts.jsonl")]
```

The node is both the **sensor** (it reports what it observes about traffic
aimed at it and about its own health) and the **enforcement point** (it can
put its outputs into a safe state). The backend does detection, scoring and
policy.

## 2. Detection pipeline

```mermaid
flowchart TD
    M["MQTT message"] --> TP{"topic valid?"}
    TP -- no --> F1["MALFORMED"]
    TP -- status --> ST{"'offline'?"} -- yes --> F2["DEVICE_OFFLINE"]
    TP -- telemetry --> K{"device registered?"}
    K -- no --> F3["UNKNOWN_DEVICE"]
    K -- yes --> D{"schema + ranges ok?"}
    D -- no --> F1
    D -- yes --> MAC{"HMAC valid?"}
    MAC -- no --> F4["TELEMETRY_AUTH_FAILURE"]
    MAC -- yes --> TR["DeviceTracker<br/>boot_id / seq / uptime state"]
    TR -- "old seq or retired boot_id" --> F5["REPLAY"]
    TR -- "new boot_id" --> F6["DEVICE_REBOOT (info)"]
    TR --> FE["6 features:<br/>rx_rate, auth_fail_rate, heap_drop_kb,<br/>wifi_reconnects, mqtt_reconnects, interval_s"]
    FE --> R1{"auth_fail ≥ 3?"} -- yes --> F7["COMMAND_REJECTIONS"]
    FE --> ML{"anomaly model loaded?"}
    ML -- no --> DG["rules-only (degraded) mode"]
    ML -- yes --> SC["IF + z-score score > 1.0?"] -- yes --> F8["ML_ANOMALY<br/>+ explanation"]
    TICK["engine.tick() every 1 s"] --> F2
```

Key properties:

* The tracker only ever sees **authenticated** telemetry, so an attacker
  cannot poison replay state by forging a high `seq`.
* The same `DeviceTracker` code produces the training features and the live
  features (no train/serve skew).
* If the model file is missing, corrupt, or was trained on a different feature
  set, the engine logs a warning and keeps running on rules only.

## 3. Risk scoring and prevention pipeline

```mermaid
flowchart TD
    F["Finding<br/>(category, confidence)"] --> RS["Risk score 0-100<br/>ML: 100 × confidence<br/>rules: base + 30 × confidence<br/>+15 if persistent"]
    RS --> SEV{"severity"}
    SEV -- "≤30 LOW" --> L["LOG"]
    SEV -- "31-60 MEDIUM" --> A["LOG + ALERT"]
    SEV -- "61-100 HIGH / CRITICAL" --> MODE{"IDPS_MODE"}
    MODE -- detect --> A
    MODE -- prevent --> P{"device-attributable<br/>AND flagged in ≥3 of last 5 windows<br/>AND not already quarantined / retry pending?"}
    P -- no --> A
    P -- yes --> Q["ALERT + signed QUARANTINE command"]
    SEV -- "CRITICAL + source_ip + firewall enabled" --> B["BLOCK_IP (experimental, dry-run default)"]
    Q --> DEV["Device: verify HMAC, freshness →<br/>drive safe-state pin, report quarantined=1"]
    DEV --> AR["Auto-release after 15 min<br/>or operator RELEASE"]
```

Why these gates exist:

| Concern | Mechanism |
|---|---|
| A single noisy window triggers an action | Persistence: 3 of the last 5 windows must be flagged |
| Uncertain detections | Scores just above threshold land in MEDIUM → alert only |
| Spoofed traffic used to make us quarantine a healthy device | Only *authenticated, device-attributable* findings (ML anomaly, command rejections) can trigger quarantine |
| Command storms from the IDPS itself | No resend once the device reports `quarantined=1`; until then at most one retry per 30 s (the device may drop commands under a flood) |
| False positive locks a device out forever | Firmware auto-releases quarantine after 15 min (configurable) |
| Operator wants an IDS, not an IPS | `IDPS_MODE=detect` (default) never acts |

## 4. Communication / sequence

```mermaid
sequenceDiagram
    autonumber
    participant D as ESP node
    participant B as MQTT broker
    participant I as IDPS backend
    D->>B: CONNECT (client id = device id, LWT status=offline, retained)
    D->>B: PUBLISH status "online" (retained)
    D->>B: SUBSCRIBE idps/v1/{id}/cmd (QoS 1)
    loop every 5 s
        D->>B: PUBLISH telemetry {counters…, mac}
        B->>I: telemetry
        I->>I: verify MAC → replay check → features → score → policy
    end
    Note over D,B: attacker floods idps/v1/{id}/cmd with forged commands
    D->>D: rate-limit parsing (5/s), reject bad MACs, count auth_fail
    D->>B: telemetry (rx_msgs↑, auth_fail↑)
    B->>I: telemetry
    I->>I: COMMAND_REJECTIONS + ML_ANOMALY, persistent → prevent mode
    I->>B: PUBLISH cmd {"ts","cmd":"QUARANTINE","mac"} (QoS 1)
    B->>D: cmd
    D->>D: verify HMAC + ts > last + |ts - NTP time| ≤ 300 s
    D->>D: safe-state pin ON, quarantined=1
    D->>B: telemetry (quarantined=1)
```

## 5. Code map

| Layer | Module | Responsibility |
|---|---|---|
| Firmware | `firmware/src/main.cpp` | Wi-Fi/MQTT state machines, watchdog, telemetry timer, quarantine |
| | `firmware/src/commands.cpp` | Command parsing, HMAC/replay/freshness checks, rate limiter |
| | `firmware/src/telemetry.cpp` | Signed telemetry serialisation |
| | `firmware/src/hmac_auth.cpp` | HMAC-SHA256 via mbedTLS / BearSSL, boot self-test |
| Wire contract | `idps/protocol.py` | Topics, canonical MAC strings, validation limits |
| Ingestion | `idps/mqtt_runtime.py` | paho-mqtt client, TLS/auth, recording |
| Features | `idps/features.py` | Per-device state, replay/reboot detection, feature vector |
| Detection | `idps/detector.py` | Isolation Forest + z-score, calibration, persistence |
| Scoring | `idps/risk.py` | Finding → score → severity |
| Policy | `idps/policy.py` | Severity + mode + persistence → actions |
| Response | `idps/response.py` | JSONL alerts, signed commands, firewall (experimental) |
| Orchestration | `idps/engine.py` | Wires the above together; dedup, cooldowns, offline detection |
| Research | `idps/synthetic.py`, `idps/evaluation.py` | Synthetic data, train/eval, benchmark |
