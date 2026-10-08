import json

import pytest
from conftest import DEVICE, KEY

from idps.protocol import command_canonical, sign
from idps.response import AlertSink, DeviceCommander, FirewallBlocker, validate_block_target


def test_commander_signs_and_keeps_ts_monotonic():
    sent = []
    clock = iter([100.0, 100.0, 99.0])  # wall clock stalls then steps back
    cmd = DeviceCommander(lambda t, p: sent.append((t, p)), {DEVICE: KEY}, "idps/v1", clock=lambda: next(clock))
    for _ in range(3):
        cmd.send(DEVICE, "PING")
    ts = [json.loads(p)["ts"] for _, p in sent]
    assert ts == [100000, 100001, 100002]
    topic, payload = sent[0]
    assert topic == "idps/v1/esp32_01/cmd"
    body = json.loads(payload)
    assert body["mac"] == sign(KEY, command_canonical(DEVICE, body["ts"], "PING"))


def test_commander_unknown_device():
    with pytest.raises(KeyError):
        DeviceCommander(lambda t, p: None, {}, "idps/v1").send("ghost", "PING")


@pytest.mark.parametrize("ip", ["192.168.1.5; rm -rf /", "1.2.3.4 & calc", "127.0.0.1", "0.0.0.0",
                                "224.0.0.1", "169.254.1.1", "::1", "not-an-ip", ""])
def test_block_target_validation_rejects_injection_and_special(ip):
    with pytest.raises(ValueError):
        validate_block_target(ip)


def test_never_block_list():
    with pytest.raises(ValueError):
        validate_block_target("192.168.1.10", never_block=["192.168.1.10"])
    assert validate_block_target(" 192.168.1.11 ") == "192.168.1.11"


@pytest.mark.parametrize("system,binary", [("Linux", "iptables"), ("Windows", "netsh")])
def test_firewall_builds_argv_without_shell_and_expires(system, binary):
    calls = []
    fw = FirewallBlocker(dry_run=False, duration_s=60, system=system, runner=calls.append)
    cmd = fw.block("203.0.113.7", now=0)
    assert cmd[0] == binary and isinstance(cmd, list)
    fw.block("203.0.113.7", now=10)  # re-block extends, does not duplicate the rule
    assert len(calls) == 1
    assert fw.expire(now=65) == []
    assert fw.expire(now=70) == ["203.0.113.7"]
    assert len(calls) == 2 and fw.active == {}


def test_firewall_dry_run_executes_nothing():
    calls = []
    fw = FirewallBlocker(dry_run=True, system="Linux", runner=calls.append)
    fw.block("203.0.113.7", now=0)
    fw.expire(now=10_000)
    assert calls == []


def test_alert_sink_writes_jsonl(tmp_path):
    sink = AlertSink(tmp_path / "a" / "alerts.jsonl")
    sink.emit({"severity": "HIGH", "actions": ["ALERT"], "detail": "x"})
    rows = (tmp_path / "a" / "alerts.jsonl").read_text().splitlines()
    assert json.loads(rows[0])["severity"] == "HIGH"
