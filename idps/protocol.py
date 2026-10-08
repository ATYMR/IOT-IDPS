"""Wire protocol shared with the firmware (see docs/protocol.md).

Everything that must match the C++ implementation byte-for-byte lives here:
topic layout, canonical strings used for HMAC, payload validation limits and
command names. ``tests/test_firmware_consistency.py`` cross-checks the
constants against ``firmware/include``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass

PROTOCOL_VERSION = 1
DEFAULT_TOPIC_PREFIX = "idps/v1"

MAX_PAYLOAD_BYTES = 1024
MAC_HEX_LEN = 64
MIN_KEY_BYTES = 16

DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

COMMANDS = ("PING", "QUARANTINE", "RELEASE")

_UINT32_MAX = 2**32 - 1
_UINT64_MAX = 2**64 - 1

# Field name -> (min, max). Order matters: it defines the canonical MAC string.
TELEMETRY_FIELDS: dict[str, tuple[int, int]] = {
    "boot_id": (0, _UINT32_MAX),
    "seq": (0, _UINT32_MAX),
    "uptime_s": (0, _UINT32_MAX),
    "rx_msgs": (0, _UINT32_MAX),
    "auth_fail": (0, _UINT32_MAX),
    "free_heap": (0, _UINT32_MAX),
    "rssi": (-127, 0),
    "wifi_reconnects": (0, _UINT32_MAX),
    "mqtt_reconnects": (0, _UINT32_MAX),
    "quarantined": (0, 1),
    "last_cmd_ts": (0, _UINT64_MAX),
}


class ProtocolError(ValueError):
    """Raised when a payload or topic violates the protocol."""


@dataclass(frozen=True)
class Telemetry:
    device_id: str
    boot_id: int
    seq: int
    uptime_s: int
    rx_msgs: int
    auth_fail: int
    free_heap: int
    rssi: int
    wifi_reconnects: int
    mqtt_reconnects: int
    quarantined: int
    last_cmd_ts: int
    mac: str

    def canonical(self) -> bytes:
        return telemetry_canonical(self.device_id, asdict(self))


# ---------------------------------------------------------------- topics

def telemetry_topic(device_id: str, prefix: str = DEFAULT_TOPIC_PREFIX) -> str:
    return f"{prefix}/{device_id}/telemetry"


def command_topic(device_id: str, prefix: str = DEFAULT_TOPIC_PREFIX) -> str:
    return f"{prefix}/{device_id}/cmd"


def status_topic(device_id: str, prefix: str = DEFAULT_TOPIC_PREFIX) -> str:
    return f"{prefix}/{device_id}/status"


def parse_topic(topic: str, prefix: str = DEFAULT_TOPIC_PREFIX) -> tuple[str, str]:
    """Split ``<prefix>/<device_id>/<kind>`` into ``(device_id, kind)``."""
    head = prefix + "/"
    if not topic.startswith(head):
        raise ProtocolError(f"topic outside prefix: {topic!r}")
    parts = topic[len(head):].split("/")
    if len(parts) != 2 or not DEVICE_ID_RE.match(parts[0]):
        raise ProtocolError(f"malformed topic: {topic!r}")
    return parts[0], parts[1]


# ---------------------------------------------------------------- HMAC

def telemetry_canonical(device_id: str, fields: dict[str, int]) -> bytes:
    values = "|".join(str(int(fields[name])) for name in TELEMETRY_FIELDS)
    return f"v{PROTOCOL_VERSION}|telemetry|{device_id}|{values}".encode("ascii")


def command_canonical(device_id: str, ts_ms: int, command: str) -> bytes:
    return f"v{PROTOCOL_VERSION}|cmd|{device_id}|{ts_ms}|{command}".encode("ascii")


def sign(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify(key: bytes, message: bytes, mac_hex: str) -> bool:
    return hmac.compare_digest(sign(key, message), mac_hex.lower())


# ---------------------------------------------------------------- telemetry

def _require_int(obj: dict, name: str, lo: int, hi: int) -> int:
    value = obj.get(name)
    # bool is a subclass of int in Python; reject it explicitly.
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProtocolError(f"field {name!r} must be an integer")
    if not lo <= value <= hi:
        raise ProtocolError(f"field {name!r} out of range: {value}")
    return value


def decode_telemetry(payload: bytes, topic_device_id: str | None = None) -> Telemetry:
    """Parse and validate a telemetry payload. Does *not* check the MAC."""
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ProtocolError(f"payload too large ({len(payload)} bytes)")
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from None
    if not isinstance(obj, dict):
        raise ProtocolError("payload must be a JSON object")

    if obj.get("v") != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {obj.get('v')!r}")

    device_id = obj.get("device_id")
    if not isinstance(device_id, str) or not DEVICE_ID_RE.match(device_id):
        raise ProtocolError("invalid device_id")
    if topic_device_id is not None and device_id != topic_device_id:
        raise ProtocolError("device_id does not match topic")

    mac = obj.get("mac")
    if not isinstance(mac, str) or len(mac) != MAC_HEX_LEN:
        raise ProtocolError("invalid mac")
    try:
        bytes.fromhex(mac)
    except ValueError:
        raise ProtocolError("invalid mac") from None

    values = {name: _require_int(obj, name, lo, hi) for name, (lo, hi) in TELEMETRY_FIELDS.items()}
    return Telemetry(device_id=device_id, mac=mac.lower(), **values)


def encode_telemetry(device_id: str, fields: dict[str, int], key: bytes) -> bytes:
    """Build a signed telemetry payload exactly as the firmware does."""
    mac = sign(key, telemetry_canonical(device_id, fields))
    body = {"v": PROTOCOL_VERSION, "device_id": device_id}
    body.update({name: int(fields[name]) for name in TELEMETRY_FIELDS})
    body["mac"] = mac
    return json.dumps(body, separators=(",", ":")).encode("ascii")


# ---------------------------------------------------------------- commands

def encode_command(device_id: str, command: str, ts_ms: int, key: bytes) -> bytes:
    if command not in COMMANDS:
        raise ProtocolError(f"unknown command {command!r}")
    if not DEVICE_ID_RE.match(device_id):
        raise ProtocolError("invalid device_id")
    mac = sign(key, command_canonical(device_id, ts_ms, command))
    return json.dumps({"ts": ts_ms, "cmd": command, "mac": mac}, separators=(",", ":")).encode("ascii")


def parse_key(hex_key: str) -> bytes:
    try:
        key = bytes.fromhex(hex_key.strip())
    except ValueError:
        raise ProtocolError("device key must be hex") from None
    if len(key) < MIN_KEY_BYTES:
        raise ProtocolError(f"device key must be at least {MIN_KEY_BYTES} bytes")
    if not any(key):
        raise ProtocolError("device key must not be all zeros (placeholder)")
    return key
