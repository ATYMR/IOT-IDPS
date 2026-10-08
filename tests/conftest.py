from __future__ import annotations

import pytest

from idps.config import Settings
from idps.evaluation import train_and_evaluate
from idps.protocol import encode_telemetry, telemetry_topic
from idps.synthetic import demo_keys, generate

KEY = bytes(range(32))
DEVICE = "esp32_01"


def telemetry_fields(**overrides) -> dict:
    fields = {
        "boot_id": 1234, "seq": 1, "uptime_s": 100, "rx_msgs": 0, "auth_fail": 0,
        "free_heap": 200_000, "rssi": -60, "wifi_reconnects": 0, "mqtt_reconnects": 0,
        "quarantined": 0, "last_cmd_ts": 0,
    }
    fields.update(overrides)
    return fields


def signed(device_id: str = DEVICE, key: bytes = KEY, **overrides) -> tuple[str, bytes]:
    return telemetry_topic(device_id), encode_telemetry(device_id, telemetry_fields(**overrides), key)


@pytest.fixture(scope="session")
def synthetic_records():
    return generate(n_windows=1600, seed=7)


@pytest.fixture(scope="session")
def trained(synthetic_records):
    """(detector, report) trained on a small synthetic dataset; shared across tests."""
    return train_and_evaluate(synthetic_records, n_estimators=100, seed=7)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(device_keys={DEVICE: KEY}, alert_log=tmp_path / "alerts.jsonl")


@pytest.fixture(scope="session")
def synthetic_keys():
    return demo_keys(7)
