"""Detection findings produced by the rule layer and the anomaly detector."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Category(str, Enum):
    ML_ANOMALY = "ml_anomaly"
    MALFORMED = "malformed_telemetry"
    TELEMETRY_AUTH_FAILURE = "telemetry_auth_failure"
    UNKNOWN_DEVICE = "unknown_device"
    REPLAY = "telemetry_replay"
    COMMAND_REJECTIONS = "device_command_rejections"
    DEVICE_OFFLINE = "device_offline"
    DEVICE_REBOOT = "device_reboot"


# Categories describing the behaviour of a specific, authenticated device.
# Only these may trigger a device-side response (quarantine): for spoofed or
# malformed traffic the sender is unknown, so commanding the device is pointless.
DEVICE_ATTRIBUTABLE = frozenset({Category.ML_ANOMALY, Category.COMMAND_REJECTIONS})


@dataclass(frozen=True)
class Finding:
    category: Category
    device_id: str | None
    confidence: float
    detail: str
    timestamp: float
    source_ip: str | None = None
    features: dict[str, float] = field(default_factory=dict)

    @property
    def device_attributable(self) -> bool:
        return self.device_id is not None and self.category in DEVICE_ATTRIBUTABLE

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        return d
