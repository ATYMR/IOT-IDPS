"""Static cross-checks between the C++ firmware and the Python protocol.

No hardware or compiler needed: these parse the firmware sources and make sure
the constants and wire formats the two sides depend on have not drifted.
"""

import re
from pathlib import Path

from idps import protocol
from idps.config import Settings
from idps.synthetic import CMD_PARSE_BUDGET_PER_S

FW = Path(__file__).resolve().parents[1] / "firmware"


def define(name: str, path: str = "include/idps_config.h") -> str:
    text = (FW / path).read_text(encoding="utf-8")
    m = re.search(rf"^#define {name}\s+(\S+)", text, re.M)
    assert m, f"{name} not found in {path}"
    return m.group(1).strip('"').rstrip("UL")


def test_protocol_constants_match():
    assert int(define("IDPS_PROTOCOL_VERSION")) == protocol.PROTOCOL_VERSION
    assert define("IDPS_TOPIC_PREFIX") == protocol.DEFAULT_TOPIC_PREFIX
    assert int(define("IDPS_HMAC_HEX_LEN")) == protocol.MAC_HEX_LEN
    assert int(define("IDPS_TELEMETRY_INTERVAL_MS")) == Settings().telemetry_interval_s * 1000
    assert int(define("IDPS_CMD_RATE_PER_S")) == CMD_PARSE_BUDGET_PER_S


def test_known_answer_vector_matches_python_hmac():
    msg = define("IDPS_KAT_MESSAGE", "include/protocol_vectors.h")
    mac = define("IDPS_KAT_MAC_HEX", "include/protocol_vectors.h")
    assert msg.encode() == protocol.command_canonical("esp32_01", 1700000000000, "PING")
    assert mac == protocol.sign(bytes(range(32)), msg.encode())


def test_telemetry_json_keys_and_canonical_order_match():
    src = (FW / "src/telemetry.cpp").read_text(encoding="utf-8")
    json_fmt = src[src.index('"{\\"v\\"'):src.index('\\"mac\\":')]
    keys = re.findall(r'\\"(\w+)\\":', json_fmt)
    assert keys == ["v", "device_id", *protocol.TELEMETRY_FIELDS]

    canon = re.search(r'"v%d\|telemetry\|%s((?:\|%\w+)+)"', src)
    assert canon, "canonical telemetry format string not found"
    assert canon.group(1).count("|") == len(protocol.TELEMETRY_FIELDS)


def test_command_names_match():
    src = (FW / "src/commands.cpp").read_text(encoding="utf-8")
    assert set(re.findall(r'strcmp\(name, "(\w+)"\)', src)) == set(protocol.COMMANDS)
    assert '"v%d|cmd|%s|%s|%s"' in src


def test_secrets_template_has_placeholder_key_only():
    text = (FW / "include/secrets.example.h").read_text(encoding="utf-8")
    key = re.search(r'IDPS_DEVICE_KEY_HEX "([0-9a-fA-F]+)"', text).group(1)
    assert set(key) == {"0"} and len(key) == 64
