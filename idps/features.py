"""Per-device state tracking and feature extraction.

The same :class:`DeviceTracker` is used for model training, offline
evaluation and live inference, so preprocessing cannot drift between them.

Only telemetry whose MAC has already been verified may be passed in: the
tracker trusts ``boot_id``/``seq`` for replay detection.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .protocol import Telemetry

FEATURE_NAMES: tuple[str, ...] = (
    "rx_rate",          # MQTT messages received by the device per second
    "auth_fail_rate",   # commands the device rejected per second
    "heap_drop_kb",     # KiB below the highest free heap seen since boot
    "wifi_reconnects",  # Wi-Fi reconnects since the previous report
    "mqtt_reconnects",  # MQTT reconnects since the previous report
    "interval_s",       # device uptime elapsed since the previous report
)

_RETIRED_BOOT_IDS = 16


@dataclass
class _DeviceState:
    boot_id: int
    seq: int
    uptime_s: int
    wifi_reconnects: int
    mqtt_reconnects: int
    max_heap: int
    last_seen: float
    quarantined: bool
    retired_boot_ids: deque = field(default_factory=lambda: deque(maxlen=_RETIRED_BOOT_IDS))


@dataclass(frozen=True)
class Observation:
    """Result of observing one authenticated telemetry message."""

    features: dict[str, float] | None  # None when the message must not be scored
    replay: bool = False
    reboot: bool = False
    replay_reason: str = ""


class DeviceTracker:
    def __init__(self, nominal_interval_s: float = 5.0) -> None:
        self.nominal_interval_s = float(nominal_interval_s)
        self._devices: dict[str, _DeviceState] = {}

    def known_devices(self) -> list[str]:
        return list(self._devices)

    def last_seen(self, device_id: str) -> float | None:
        st = self._devices.get(device_id)
        return st.last_seen if st else None

    def is_quarantined(self, device_id: str) -> bool:
        st = self._devices.get(device_id)
        return bool(st and st.quarantined)

    def forget(self, device_id: str) -> None:
        self._devices.pop(device_id, None)

    def _fresh_state(self, t: Telemetry, now: float) -> _DeviceState:
        return _DeviceState(
            boot_id=t.boot_id, seq=t.seq, uptime_s=t.uptime_s,
            wifi_reconnects=t.wifi_reconnects, mqtt_reconnects=t.mqtt_reconnects,
            max_heap=t.free_heap, last_seen=now, quarantined=bool(t.quarantined),
        )

    def _baseline_features(self, t: Telemetry) -> dict[str, float]:
        interval = self.nominal_interval_s
        return {
            "rx_rate": t.rx_msgs / interval,
            "auth_fail_rate": t.auth_fail / interval,
            "heap_drop_kb": 0.0,
            "wifi_reconnects": 0.0,
            "mqtt_reconnects": 0.0,
            "interval_s": interval,
        }

    def observe(self, t: Telemetry, now: float) -> Observation:
        st = self._devices.get(t.device_id)

        if st is None:
            self._devices[t.device_id] = self._fresh_state(t, now)
            return Observation(features=self._baseline_features(t))

        if t.boot_id in st.retired_boot_ids:
            return Observation(features=None, replay=True,
                               replay_reason=f"boot_id {t.boot_id} belongs to an earlier boot")

        if t.boot_id != st.boot_id:
            retired = st.retired_boot_ids
            retired.append(st.boot_id)
            new = self._fresh_state(t, now)
            new.retired_boot_ids = retired
            self._devices[t.device_id] = new
            return Observation(features=self._baseline_features(t), reboot=True)

        if t.seq <= st.seq:
            return Observation(features=None, replay=True,
                               replay_reason=f"seq {t.seq} <= last accepted seq {st.seq}")

        interval = float(max(t.uptime_s - st.uptime_s, 1))
        st.max_heap = max(st.max_heap, t.free_heap)
        features = {
            "rx_rate": t.rx_msgs / interval,
            "auth_fail_rate": t.auth_fail / interval,
            "heap_drop_kb": (st.max_heap - t.free_heap) / 1024.0,
            "wifi_reconnects": float(max(t.wifi_reconnects - st.wifi_reconnects, 0)),
            "mqtt_reconnects": float(max(t.mqtt_reconnects - st.mqtt_reconnects, 0)),
            "interval_s": interval,
        }
        st.seq = t.seq
        st.uptime_s = t.uptime_s
        st.wifi_reconnects = t.wifi_reconnects
        st.mqtt_reconnects = t.mqtt_reconnects
        st.last_seen = now
        st.quarantined = bool(t.quarantined)
        return Observation(features=features)


def feature_vector(features: dict[str, float]) -> list[float]:
    return [float(features[name]) for name in FEATURE_NAMES]
