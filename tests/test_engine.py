import json

import pytest
from conftest import DEVICE, KEY, signed

from idps.config import Settings
from idps.engine import EngineTuning, IDPSEngine
from idps.findings import Category
from idps.policy import Action
from idps.response import AlertSink, DeviceCommander


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_engine(tmp_path, detector=None, mode="detect", **tuning):
    clock = Clock()
    sent = []
    settings = Settings(device_keys={DEVICE: KEY}, mode=mode, alert_log=tmp_path / "alerts.jsonl")
    commander = DeviceCommander(lambda t, p: sent.append((t, p)), settings.device_keys,
                                settings.topic_prefix, clock=clock)
    engine = IDPSEngine(settings, detector, AlertSink(settings.alert_log), commander,
                        tuning=EngineTuning(**tuning), clock=clock)
    return engine, clock, sent


def cats(decisions):
    return [d.finding.category for d in decisions]


def test_valid_normal_telemetry_produces_no_findings(tmp_path, trained):
    engine, clock, _ = make_engine(tmp_path, trained[0])
    for seq in range(1, 6):
        clock.now += 5
        assert engine.handle_message(*signed(seq=seq, uptime_s=100 + 5 * seq)) == []


def test_spoofed_telemetry_detected(tmp_path):
    engine, _, _ = make_engine(tmp_path)
    topic, payload = signed(key=bytes(range(1, 33)))
    assert cats(engine.handle_message(topic, payload)) == [Category.TELEMETRY_AUTH_FAILURE]


def test_unknown_device_and_malformed(tmp_path):
    engine, _, _ = make_engine(tmp_path)
    topic, payload = signed(device_id="intruder")
    assert cats(engine.handle_message(topic, payload)) == [Category.UNKNOWN_DEVICE]
    assert cats(engine.handle_message("idps/v1/esp32_01/telemetry", b"{oops")) == [Category.MALFORMED]
    assert cats(engine.handle_message("weird/topic", b"x")) == [Category.MALFORMED]


def test_replay_detected(tmp_path):
    engine, _, _ = make_engine(tmp_path)
    msg = signed(seq=3)
    assert engine.handle_message(*msg) == []
    assert cats(engine.handle_message(*msg)) == [Category.REPLAY]


def test_rules_only_mode_without_model(tmp_path):
    engine, _, _ = make_engine(tmp_path, detector=None)
    decisions = engine.handle_message(*signed(auth_fail=12, rx_msgs=12))
    assert cats(decisions) == [Category.COMMAND_REJECTIONS]


def test_flood_in_prevent_mode_quarantines_after_persistence(tmp_path, trained):
    engine, clock, sent = make_engine(tmp_path, trained[0], mode="prevent")
    engine.handle_message(*signed(seq=1, uptime_s=100))
    quarantined_at = None
    for seq in range(2, 8):
        clock.now += 5
        decisions = engine.handle_message(*signed(seq=seq, uptime_s=95 + 5 * seq, rx_msgs=150, auth_fail=25))
        if any(Action.QUARANTINE_DEVICE in d.actions for d in decisions):
            quarantined_at = quarantined_at or seq
    assert quarantined_at == 4  # third consecutive flagged window (persistence 3 of 5)
    assert len(sent) == 1  # cooldown prevents repeated commands
    topic, payload = sent[0]
    assert topic.endswith("/esp32_01/cmd") and json.loads(payload)["cmd"] == "QUARANTINE"


def test_detect_mode_sends_nothing(tmp_path, trained):
    engine, clock, sent = make_engine(tmp_path, trained[0], mode="detect")
    engine.handle_message(*signed(seq=1, uptime_s=100))
    for seq in range(2, 10):
        clock.now += 5
        engine.handle_message(*signed(seq=seq, uptime_s=95 + 5 * seq, rx_msgs=150, auth_fail=25))
    assert sent == []


def test_device_reporting_quarantined_is_not_recommanded(tmp_path, trained):
    engine, clock, sent = make_engine(tmp_path, trained[0], mode="prevent", quarantine_cooldown_s=0)
    engine.handle_message(*signed(seq=1, uptime_s=100, quarantined=1))
    for seq in range(2, 10):
        clock.now += 5
        engine.handle_message(*signed(seq=seq, uptime_s=95 + 5 * seq, rx_msgs=150, auth_fail=25, quarantined=1))
    assert sent == []


def test_offline_detection_and_lwt(tmp_path):
    engine, clock, _ = make_engine(tmp_path)
    engine.handle_message(*signed(seq=1))
    clock.now += 5
    assert engine.tick() == []
    clock.now += 60
    assert cats(engine.tick()) == [Category.DEVICE_OFFLINE]
    assert engine.tick() == []  # reported once
    engine.handle_message(*signed(seq=2, uptime_s=165))
    assert cats(engine.handle_message("idps/v1/esp32_01/status", b"offline")) == [Category.DEVICE_OFFLINE]
    assert engine.handle_message("idps/v1/ghost/status", b"offline") == []


def test_alert_dedup(tmp_path):
    engine, clock, _ = make_engine(tmp_path, dedup_s=30)
    first = engine.handle_message(*signed(seq=1, auth_fail=10))
    clock.now += 5
    second = engine.handle_message(*signed(seq=2, uptime_s=105, auth_fail=10))
    assert not first[0].suppressed and second[0].suppressed
    lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
    assert len(lines) == 1


def test_engine_survives_quarantine_publish_failure(tmp_path, trained):
    engine, clock, _ = make_engine(tmp_path, trained[0], mode="prevent")

    def boom(topic, payload):
        raise ConnectionError("broker down")

    engine.commander._publish = boom
    engine.handle_message(*signed(seq=1, uptime_s=100))
    for seq in range(2, 7):
        clock.now += 5
        decisions = engine.handle_message(*signed(seq=seq, uptime_s=95 + 5 * seq, rx_msgs=150, auth_fail=25))
        assert all(Action.QUARANTINE_DEVICE not in d.actions for d in decisions)


@pytest.mark.parametrize("payload", [b"", b"\x00" * 5000, b'{"v":1}', b"[]"])
def test_fuzz_inputs_never_raise(tmp_path, payload):
    engine, _, _ = make_engine(tmp_path)
    engine.handle_message("idps/v1/esp32_01/telemetry", payload)


def test_random_unregistered_ids_do_not_grow_state_or_flood_alerts(tmp_path):
    engine, clock, _ = make_engine(tmp_path, dedup_s=30)
    for i in range(500):
        engine.handle_message(*signed(device_id=f"ghost{i}"))
    lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
    assert len(lines) == 1  # aggregated as one source
    clock.now += 31
    engine.tick()
    assert engine._last_emitted == {}
    assert engine.tracker.known_devices() == []
