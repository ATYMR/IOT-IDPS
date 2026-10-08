"""Runtime configuration, loaded from environment variables (optionally a .env file).

Secrets (MQTT password, device HMAC keys) are only ever read from the
environment; see ``.env.example`` for the full list of variables.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .protocol import DEFAULT_TOPIC_PREFIX, DEVICE_ID_RE, ProtocolError, parse_key

MODES = ("detect", "prevent")


class ConfigError(ValueError):
    pass


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"invalid boolean: {value!r}")


def _int(value: str | None, default: int, lo: int, hi: int, name: str) -> int:
    if value is None or value == "":
        return default
    try:
        n = int(value)
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None
    if not lo <= n <= hi:
        raise ConfigError(f"{name} must be in [{lo}, {hi}]")
    return n


def parse_device_keys(spec: str) -> dict[str, bytes]:
    """Parse ``device_a:hexkey,device_b:hexkey``."""
    keys: dict[str, bytes] = {}
    for item in filter(None, (s.strip() for s in spec.split(","))):
        device_id, sep, hex_key = item.partition(":")
        device_id = device_id.strip()
        if not sep or not DEVICE_ID_RE.match(device_id):
            raise ConfigError(f"invalid IDPS_DEVICE_KEYS entry for {device_id!r}")
        if device_id in keys:
            raise ConfigError(f"duplicate key for device {device_id!r}")
        try:
            keys[device_id] = parse_key(hex_key)
        except ProtocolError as exc:
            raise ConfigError(f"{device_id}: {exc}") from None
    return keys


@dataclass(frozen=True)
class Settings:
    mqtt_host: str = "localhost"
    mqtt_port: int = 1883
    mqtt_username: str | None = None
    mqtt_password: str | None = field(default=None, repr=False)
    mqtt_tls: bool = False
    mqtt_ca_file: str | None = None
    mqtt_client_id: str = "idps-backend"
    topic_prefix: str = DEFAULT_TOPIC_PREFIX
    device_keys: dict[str, bytes] = field(default_factory=dict, repr=False)
    mode: str = "detect"
    model_path: Path = Path("models/isolation_forest.joblib")
    alert_log: Path = Path("logs/alerts.jsonl")
    telemetry_interval_s: int = 5
    firewall_enabled: bool = False
    firewall_dry_run: bool = True

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ConfigError(f"IDPS_MODE must be one of {MODES}")
        if self.mqtt_ca_file and not self.mqtt_tls:
            raise ConfigError("IDPS_MQTT_CA_FILE is set but IDPS_MQTT_TLS is off")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        return cls(
            mqtt_host=e.get("IDPS_MQTT_HOST", "localhost"),
            mqtt_port=_int(e.get("IDPS_MQTT_PORT"), 1883, 1, 65535, "IDPS_MQTT_PORT"),
            mqtt_username=e.get("IDPS_MQTT_USERNAME") or None,
            mqtt_password=e.get("IDPS_MQTT_PASSWORD") or None,
            mqtt_tls=_bool(e.get("IDPS_MQTT_TLS"), False),
            mqtt_ca_file=e.get("IDPS_MQTT_CA_FILE") or None,
            mqtt_client_id=e.get("IDPS_MQTT_CLIENT_ID", "idps-backend"),
            topic_prefix=e.get("IDPS_TOPIC_PREFIX", DEFAULT_TOPIC_PREFIX).rstrip("/"),
            device_keys=parse_device_keys(e.get("IDPS_DEVICE_KEYS", "")),
            mode=e.get("IDPS_MODE", "detect").strip().lower(),
            model_path=Path(e.get("IDPS_MODEL_PATH", "models/isolation_forest.joblib")),
            alert_log=Path(e.get("IDPS_ALERT_LOG", "logs/alerts.jsonl")),
            telemetry_interval_s=_int(e.get("IDPS_TELEMETRY_INTERVAL_S"), 5, 1, 3600,
                                      "IDPS_TELEMETRY_INTERVAL_S"),
            firewall_enabled=_bool(e.get("IDPS_FIREWALL_ENABLED"), False),
            firewall_dry_run=_bool(e.get("IDPS_FIREWALL_DRY_RUN"), True),
        )


def load_settings(env_file: str | os.PathLike | None = ".env") -> Settings:
    """Load ``.env`` (if present, without overriding real env vars) then build Settings."""
    if env_file and Path(env_file).is_file():
        from dotenv import load_dotenv

        load_dotenv(env_file, override=False)
    return Settings.from_env()
