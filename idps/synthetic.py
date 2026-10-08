"""Synthetic telemetry generator and dataset I/O.

THIS DATA IS SIMULATED. It exists so the pipeline can be developed, tested
and demonstrated without hardware. The behaviour models below are plausible
engineering assumptions, not measurements; results obtained on this data say
nothing about real-world detection performance. Use ``idps listen --record``
to capture real telemetry from your own devices instead.

Each record is a signed payload in the exact firmware wire format, so it goes
through the same parsing, MAC verification and feature extraction as live data.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .protocol import DEFAULT_TOPIC_PREFIX, encode_telemetry, telemetry_topic

ATTACK_TYPES = ("cmd_flood", "forged_cmd", "wifi_deauth", "clientid_hijack", "heap_exhaustion")
NORMAL = "normal"

# Device rejects at most this many command messages per second; the rest are
# dropped unparsed (mirrors IDPS_CMD_RATE_PER_S in the firmware).
CMD_PARSE_BUDGET_PER_S = 5


@dataclass(frozen=True)
class DeviceProfile:
    device_id: str
    base_heap: int


DEFAULT_PROFILES = (
    DeviceProfile("esp32_01", 210_000),
    DeviceProfile("esp32_02", 204_000),
    DeviceProfile("esp8266_01", 41_000),
)


@dataclass(frozen=True)
class Record:
    t: float
    topic: str
    payload: bytes
    label: str


def demo_key(device_id: str, seed: int) -> bytes:
    """Deterministic key for SYNTHETIC data only. Never use for real devices."""
    return hashlib.sha256(f"idps-synthetic-demo-key|{seed}|{device_id}".encode()).digest()


def _episodes(rng: np.random.Generator, start: int, end: int) -> list[tuple[int, int, str, float]]:
    episodes, cursor = [], start
    while True:
        begin = cursor + int(rng.integers(20, 120))
        length = int(rng.integers(6, 40))
        if begin + length >= end:
            return episodes
        episodes.append((begin, begin + length, str(rng.choice(ATTACK_TYPES)), float(rng.uniform(0, 1))))
        cursor = begin + length


def _simulate_device(profile: DeviceProfile, n_windows: int, interval_s: int, attack_start: int,
                     seed: int, rng: np.random.Generator, prefix: str) -> list[Record]:
    key = demo_key(profile.device_id, seed)
    episodes = _episodes(rng, attack_start, n_windows)

    def new_boot() -> dict:
        return {"boot_id": int(rng.integers(1, 2**32)), "seq": 0, "uptime_s": int(rng.integers(30, 120))}

    boot = new_boot()
    wifi_rc = mqtt_rc = 0
    t = float(rng.uniform(0, interval_s))
    leak = 0.0
    records: list[Record] = []

    for w in range(n_windows):
        label, intensity = NORMAL, 0.0
        for begin, finish, kind, inten in episodes:
            if begin <= w < finish:
                label, intensity = kind, inten
                break

        interval = interval_s * (2 if rng.random() < 0.002 else 1)  # occasional missed publish
        rx = int(rng.poisson(0.01))  # rare legitimate commands
        auth_fail = 0
        heap = profile.base_heap + rng.normal(0, 600)
        if rng.random() < 0.01:  # benign transient allocation (e.g. TLS buffers)
            heap -= rng.uniform(1500, 6000)
        wifi_inc = int(rng.random() < 0.001)
        mqtt_inc = int(wifi_inc or rng.random() < 0.002)

        if label == "cmd_flood":
            rate = 0.2 + 30 * intensity
            flood = int(rng.poisson(rate * interval))
            rx += flood
            auth_fail += min(flood, CMD_PARSE_BUDGET_PER_S * interval)
            heap -= rng.uniform(0, 1500) * intensity
            if intensity > 0.7 and rng.random() < 0.3:
                interval += 1  # loop starved by message handling
        elif label == "forged_cmd":
            forged = int(rng.poisson((0.02 + 1.0 * intensity) * interval))
            rx += forged
            auth_fail += forged
        elif label == "wifi_deauth":
            if rng.random() < 0.15 + 0.85 * intensity:
                wifi_inc, mqtt_inc = 1, 1
                interval += int(rng.integers(2, 15))  # time spent disconnected
        elif label == "clientid_hijack":
            if rng.random() < 0.15 + 0.85 * intensity:
                mqtt_inc += 1 + int(rng.poisson(intensity))
        elif label == "heap_exhaustion":
            leak += 100 + 2500 * intensity
            heap -= leak
        if label != "heap_exhaustion":
            leak = 0.0

        # Reboot: rare benign restarts, or out-of-memory under heap exhaustion.
        if (label == NORMAL and rng.random() < 0.0005) or heap < 0.1 * profile.base_heap:
            boot, leak, wifi_rc, mqtt_rc, wifi_inc, mqtt_inc = new_boot(), 0.0, 0, 0, 0, 0
            heap = profile.base_heap + rng.normal(0, 600)

        wifi_rc += wifi_inc
        mqtt_rc += mqtt_inc
        t += interval
        boot["uptime_s"] += interval
        boot["seq"] += 1
        fields = {
            "boot_id": boot["boot_id"], "seq": boot["seq"], "uptime_s": boot["uptime_s"],
            "rx_msgs": rx, "auth_fail": auth_fail, "free_heap": int(max(heap, 0)),
            "rssi": int(np.clip(rng.normal(-62, 4), -95, -30)),
            "wifi_reconnects": wifi_rc, "mqtt_reconnects": mqtt_rc,
            "quarantined": 0, "last_cmd_ts": 0,
        }
        payload = encode_telemetry(profile.device_id, fields, key)
        records.append(Record(t, telemetry_topic(profile.device_id, prefix), payload, label))
    return records


def generate(n_windows: int = 4000, seed: int = 42, attack_start_fraction: float = 0.75,
             interval_s: int = 5, profiles: tuple[DeviceProfile, ...] = DEFAULT_PROFILES,
             prefix: str = DEFAULT_TOPIC_PREFIX) -> list[Record]:
    """Generate per-device streams; attacks are only injected after ``attack_start_fraction``."""
    rng = np.random.default_rng(seed)
    attack_start = int(n_windows * attack_start_fraction)
    records: list[Record] = []
    for profile in profiles:
        records += _simulate_device(profile, n_windows, interval_s, attack_start, seed, rng, prefix)
    records.sort(key=lambda r: r.t)
    return records


def demo_keys(seed: int, profiles: tuple[DeviceProfile, ...] = DEFAULT_PROFILES) -> dict[str, bytes]:
    return {p.device_id: demo_key(p.device_id, seed) for p in profiles}


# ---------------------------------------------------------------- dataset I/O

def save_jsonl(records: list[Record], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps({"t": r.t, "topic": r.topic,
                                 "payload": r.payload.decode("utf-8"), "label": r.label}) + "\n")


def load_jsonl(path: str | Path) -> list[Record]:
    records = []
    with Path(path).open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                records.append(Record(float(obj["t"]), str(obj["topic"]),
                                      str(obj["payload"]).encode("utf-8"), str(obj.get("label", "unlabeled"))))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{lineno}: invalid record ({exc})") from None
    return records
