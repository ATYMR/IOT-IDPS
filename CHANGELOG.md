# Changelog

## 0.2.0 — complete rework of the 0.1.0 prototype

The 0.1.0 prototype was three disconnected parts: ESP sketches publishing to
a public broker, an Isolation Forest trained on unrelated simulated features
(CPU, packet rate, temperature) that the devices never sent, and a
risk/policy/firewall chain driven by a hardcoded fake detection.

### Fixed
- Commands from a public broker were unauthenticated, so anyone could
  disconnect the device. Commands are now HMAC-signed and replay-protected.
- Wi-Fi credentials were hardcoded in the firmware. They now live in a
  git-ignored `secrets.h`.
- `main.py` sent a `DISCONNECT` command on import.
- The firewall blocker used `shell=True` with an unvalidated IP and blocked
  the pipeline with `sleep()`.
- `contamination=0.1` on normal-only training data forced ~10 % false
  positives (visible in the old `alerts.log`).
- The model was evaluated on its own training data.
- The `DISCONNECT` handler left the ESP8266 stuck in a busy reconnect loop.
  The `QUARANTINE` handler did nothing.
- `msg_rate` was a monotonic counter and `auth_fail` was always 0.
- paho-mqtt 2.x deprecation (`Client()` without a callback API version).

### Added
- A single firmware codebase for ESP32 and ESP8266: non-blocking reconnects,
  watchdog, signed telemetry, authenticated commands, quarantine safe-state
  with auto-release, last will, boot-time HMAC self-test, optional TLS.
- The `idps` Python package: validated wire protocol, per-device feature
  tracking with replay detection, Isolation Forest + z-score detector,
  risk/policy with `detect`/`prevent` modes, persistence and cooldowns, JSONL
  alerts, and a CLI.
- A leakage-free evaluation pipeline with baselines, ablations, episode
  metrics, latency, and a multi-seed benchmark.
- 160+ tests, including firmware code compiled on the host and a live MQTT
  integration test. GitHub Actions CI.
- Documentation: architecture, protocol, security model, evaluation, hardware.

### Removed
- Legacy scripts (`live_detector.py`, `visualize.py`, duplicated listeners,
  `main.py`, …) and the committed CSV/log artifacts. The original files are
  preserved outside the repository.
- Public broker defaults.
- The unimplemented `RATE_LIMIT` policy action.
