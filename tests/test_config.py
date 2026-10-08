import pytest

from idps.config import ConfigError, Settings, parse_device_keys

K1 = "11" * 32
K2 = "22" * 32


def test_defaults_are_safe():
    s = Settings.from_env({})
    assert s.mode == "detect"
    assert s.firewall_enabled is False and s.firewall_dry_run is True
    assert s.device_keys == {}


def test_full_env():
    s = Settings.from_env({
        "IDPS_MQTT_HOST": "broker.lan", "IDPS_MQTT_PORT": "8883", "IDPS_MQTT_TLS": "true",
        "IDPS_MQTT_USERNAME": "idps", "IDPS_MQTT_PASSWORD": "pw", "IDPS_MODE": "PREVENT",
        "IDPS_DEVICE_KEYS": f"esp32_01:{K1}, esp8266_01:{K2}", "IDPS_TOPIC_PREFIX": "lab/idps/",
    })
    assert s.mqtt_port == 8883 and s.mqtt_tls and s.mode == "prevent"
    assert set(s.device_keys) == {"esp32_01", "esp8266_01"}
    assert s.topic_prefix == "lab/idps"


def test_secrets_not_in_repr():
    s = Settings.from_env({"IDPS_MQTT_PASSWORD": "hunter2", "IDPS_DEVICE_KEYS": f"a:{K1}"})
    assert "hunter2" not in repr(s) and K1 not in repr(s)


@pytest.mark.parametrize("env", [
    {"IDPS_MODE": "attack"},
    {"IDPS_MQTT_PORT": "0"},
    {"IDPS_MQTT_PORT": "http"},
    {"IDPS_MQTT_TLS": "maybe"},
    {"IDPS_MQTT_CA_FILE": "ca.pem"},
    {"IDPS_DEVICE_KEYS": "esp32_01"},
    {"IDPS_DEVICE_KEYS": f"bad id:{K1}"},
    {"IDPS_DEVICE_KEYS": "esp32_01:1234"},
    {"IDPS_DEVICE_KEYS": "esp32_01:" + "00" * 32},
    {"IDPS_DEVICE_KEYS": f"a:{K1},a:{K2}"},
])
def test_invalid_config_rejected(env):
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_parse_device_keys_ignores_blank_entries():
    assert list(parse_device_keys(f",a:{K1},,")) == ["a"]
