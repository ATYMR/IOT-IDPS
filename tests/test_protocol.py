import json

import pytest
from conftest import DEVICE, KEY, signed, telemetry_fields

from idps import protocol as p


def test_roundtrip_and_mac_verifies():
    _, payload = signed()
    t = p.decode_telemetry(payload, DEVICE)
    assert t.seq == 1 and t.free_heap == 200_000
    assert p.verify(KEY, t.canonical(), t.mac)


def test_wrong_key_fails_verification():
    _, payload = signed()
    t = p.decode_telemetry(payload, DEVICE)
    assert not p.verify(bytes(32 * [7]), t.canonical(), t.mac)


@pytest.mark.parametrize("field,value", [("seq", 2), ("auth_fail", 9), ("quarantined", 1)])
def test_tampered_field_breaks_mac(field, value):
    _, payload = signed()
    obj = json.loads(payload)
    obj[field] = value
    t = p.decode_telemetry(json.dumps(obj).encode(), DEVICE)
    assert not p.verify(KEY, t.canonical(), t.mac)


def test_device_id_is_bound_into_mac():
    # A valid message for esp32_01 relabelled as esp32_02 must not verify.
    _, payload = signed()
    obj = json.loads(payload)
    obj["device_id"] = "esp32_02"
    t = p.decode_telemetry(json.dumps(obj).encode(), "esp32_02")
    assert not p.verify(KEY, t.canonical(), t.mac)


@pytest.mark.parametrize("mutate", [
    lambda o: o.pop("seq"),
    lambda o: o.update(seq="1"),
    lambda o: o.update(seq=True),
    lambda o: o.update(seq=-1),
    lambda o: o.update(seq=2**32),
    lambda o: o.update(rssi=5),
    lambda o: o.update(quarantined=2),
    lambda o: o.update(v=2),
    lambda o: o.update(device_id="bad id!"),
    lambda o: o.update(mac="zz" * 32),
    lambda o: o.update(mac="ab"),
])
def test_invalid_fields_rejected(mutate):
    _, payload = signed()
    obj = json.loads(payload)
    mutate(obj)
    topic_device = obj.get("device_id") if isinstance(obj.get("device_id"), str) else None
    with pytest.raises(p.ProtocolError):
        p.decode_telemetry(json.dumps(obj).encode(), topic_device)


@pytest.mark.parametrize("payload", [b"", b"not json", b"[1,2]", b"\xff\xfe", b"{" * 2000, b"null"])
def test_garbage_rejected(payload):
    with pytest.raises(p.ProtocolError):
        p.decode_telemetry(payload)


def test_topic_mismatch_rejected():
    _, payload = signed()
    with pytest.raises(p.ProtocolError):
        p.decode_telemetry(payload, "esp32_99")


@pytest.mark.parametrize("topic", ["idps/v1/esp32_01", "idps/v1/a/b/c", "other/esp32_01/telemetry",
                                   "idps/v1/../telemetry", "idps/v1/x y/telemetry"])
def test_bad_topics(topic):
    with pytest.raises(p.ProtocolError):
        p.parse_topic(topic)


def test_parse_topic_ok():
    assert p.parse_topic("idps/v1/esp32_01/telemetry") == ("esp32_01", "telemetry")


def test_command_encoding_and_canonical_form():
    payload = json.loads(p.encode_command(DEVICE, "QUARANTINE", 1_700_000_000_123, KEY))
    assert payload["cmd"] == "QUARANTINE" and payload["ts"] == 1_700_000_000_123
    expected = p.sign(KEY, b"v1|cmd|esp32_01|1700000000123|QUARANTINE")
    assert payload["mac"] == expected


def test_unknown_command_rejected():
    with pytest.raises(p.ProtocolError):
        p.encode_command(DEVICE, "REBOOT", 1, KEY)


def test_canonical_telemetry_field_order_is_stable():
    canon = p.telemetry_canonical(DEVICE, telemetry_fields())
    assert canon == b"v1|telemetry|esp32_01|1234|1|100|0|0|200000|-60|0|0|0|0"


@pytest.mark.parametrize("bad", ["", "abc", "00" * 32, "11" * 8])
def test_parse_key_rejects_weak_keys(bad):
    with pytest.raises(p.ProtocolError):
        p.parse_key(bad)
