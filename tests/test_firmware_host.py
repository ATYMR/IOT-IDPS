"""Compile the firmware's command/telemetry code for the host and cross-test it
against the Python backend. Skipped when no C++ compiler or ArduinoJson
headers are available (CI provides both after the PlatformIO build).

Set IDPS_ARDUINOJSON_INCLUDE to ArduinoJson's ``src`` directory if it is not
under ``firmware/.pio/libdeps``.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from idps import protocol

ROOT = Path(__file__).resolve().parents[1]
FW = ROOT / "firmware"
KEY = bytes(range(1, 33))
DEVICE = "esp32_01"


def _arduinojson_include() -> Path | None:
    env = os.environ.get("IDPS_ARDUINOJSON_INCLUDE")
    if env and (Path(env) / "ArduinoJson.h").is_file():
        return Path(env)
    for candidate in sorted(FW.glob(".pio/libdeps/*/ArduinoJson/src")):
        if (candidate / "ArduinoJson.h").is_file():
            return candidate
    return None


@pytest.fixture(scope="module")
def harness(tmp_path_factory) -> Path:
    cxx = os.environ.get("CXX") or shutil.which("g++") or shutil.which("clang++")
    aj = _arduinojson_include()
    if not cxx or not aj:
        pytest.skip("host C++ compiler or ArduinoJson headers not available")
    exe = tmp_path_factory.mktemp("fw") / "host_harness"
    sources = [FW / "src/commands.cpp", FW / "src/hmac_auth.cpp", FW / "src/telemetry.cpp",
               *sorted((FW / "test/host").glob("*.cpp"))]
    cmd = [cxx, "-std=c++14", "-O1", "-Wall", "-Werror", "-DIDPS_HOST_TEST", "-DARDUINOJSON_USE_LONG_LONG=1",
           f"-I{FW / 'include'}", f"-I{FW / 'src'}", "-isystem", str(aj), *map(str, sources), "-o", str(exe)]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return exe


def run(harness, *args, stdin: bytes = b"") -> str:
    out = subprocess.run([str(harness), *map(str, args)], input=stdin, capture_output=True, check=True)
    return out.stdout.decode().strip()


def command(harness, payload: bytes, last_ts=0, synced=True, now_ms=None, device=DEVICE, key=KEY):
    now_ms = 1_700_000_000_000 if now_ms is None else now_ms
    return run(harness, "command", device, key.hex(), last_ts, int(synced), now_ms, stdin=payload).split()


def test_known_answer_test(harness):
    assert run(harness, "kat") == "PASS"


def test_rate_limiter(harness):
    assert run(harness, "ratelimit") == "111110011"


@pytest.mark.parametrize("name,code", [("PING", "1"), ("QUARANTINE", "2"), ("RELEASE", "3")])
def test_backend_commands_are_accepted(harness, name, code):
    ts = 1_700_000_000_123
    verdict, cmd, echoed = command(harness, protocol.encode_command(DEVICE, name, ts, KEY))
    assert (verdict, cmd, echoed) == ("accepted", code, str(ts))


def test_rejections(harness):
    ts = 1_700_000_000_000
    good = protocol.encode_command(DEVICE, "QUARANTINE", ts, KEY)
    assert command(harness, good, key=bytes(32 * [9]))[0] == "bad_mac"
    assert command(harness, good, device="esp32_02")[0] == "bad_mac"  # MAC binds the device id
    assert command(harness, good, last_ts=ts)[0] == "replay"
    assert command(harness, good, synced=False)[0] == "no_time_sync"
    assert command(harness, good, now_ms=ts + 301_000)[0] == "stale"
    assert command(harness, good, now_ms=ts - 299_000)[0] == "accepted"


def test_uppercase_mac_accepted(harness):
    body = json.loads(protocol.encode_command(DEVICE, "PING", 1_700_000_000_000, KEY))
    body["mac"] = body["mac"].upper()
    assert command(harness, json.dumps(body).encode())[0] == "accepted"


@pytest.mark.parametrize("payload,verdict", [
    (b"", "malformed"),
    (b"garbage", "malformed"),
    (b'{"ts":-5,"cmd":"PING","mac":"00"}', "malformed"),
    (b'{"ts":"1","cmd":"PING","mac":"00"}', "malformed"),
    (b'{"ts":1,"cmd":{"x":1},"mac":"00"}', "malformed"),
    (b'{"ts":1,"cmd":"PING"}', "malformed"),
    (b'{"ts":1,"cmd":"REBOOT","mac":"' + b"0" * 64 + b'"}', "unknown_command"),
    (b'{"ts":1,"cmd":"PING","mac":"' + b"0" * 64 + b'"}', "bad_mac"),
    (b'{"ts":1,"cmd":"PING","mac":"abc"}', "bad_mac"),
    (b"x" * 300, "too_long"),
])
def test_malformed_commands(harness, payload, verdict):
    assert command(harness, payload)[0] == verdict


@pytest.mark.parametrize("fields", [
    dict(boot_id=1, seq=1, uptime_s=5, rx_msgs=0, auth_fail=0, free_heap=210_000, rssi=-61,
         wifi_reconnects=0, mqtt_reconnects=0, quarantined=0, last_cmd_ts=0),
    dict(boot_id=2**32 - 1, seq=2**32 - 1, uptime_s=2**32 - 1, rx_msgs=12345, auth_fail=99, free_heap=40_000,
         rssi=-127, wifi_reconnects=7, mqtt_reconnects=8, quarantined=1, last_cmd_ts=2**64 - 1),
])
def test_firmware_telemetry_verifies_in_backend(harness, fields):
    args = [fields[k] for k in protocol.TELEMETRY_FIELDS]
    out = run(harness, "telemetry", DEVICE, KEY.hex(), *args).encode()
    t = protocol.decode_telemetry(out, DEVICE)
    assert protocol.verify(KEY, t.canonical(), t.mac)
    # Byte-identical to what the backend's own encoder produces.
    assert out == protocol.encode_telemetry(DEVICE, fields, KEY)


def test_positive_rssi_is_clamped(harness):
    args = [1, 1, 5, 0, 0, 1000, 31, 0, 0, 0, 0]
    t = protocol.decode_telemetry(run(harness, "telemetry", DEVICE, KEY.hex(), *args).encode(), DEVICE)
    assert t.rssi == 0 and protocol.verify(KEY, t.canonical(), t.mac)
