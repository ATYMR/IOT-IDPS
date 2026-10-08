from conftest import DEVICE, signed

from idps.features import FEATURE_NAMES, DeviceTracker, feature_vector
from idps.protocol import decode_telemetry


def tel(**kw):
    return decode_telemetry(signed(**kw)[1], DEVICE)


def test_first_message_uses_nominal_interval():
    obs = DeviceTracker(5).observe(tel(rx_msgs=10), now=0)
    assert obs.features["rx_rate"] == 2.0
    assert obs.features["interval_s"] == 5.0
    assert not obs.replay and not obs.reboot


def test_rates_and_deltas():
    tr = DeviceTracker(5)
    tr.observe(tel(seq=1, uptime_s=100, wifi_reconnects=2, mqtt_reconnects=3, free_heap=200_000), 0)
    obs = tr.observe(tel(seq=2, uptime_s=110, rx_msgs=20, auth_fail=5, wifi_reconnects=3,
                         mqtt_reconnects=5, free_heap=200_000 - 4096), 10)
    f = obs.features
    assert f["interval_s"] == 10
    assert f["rx_rate"] == 2.0 and f["auth_fail_rate"] == 0.5
    assert f["wifi_reconnects"] == 1 and f["mqtt_reconnects"] == 2
    assert f["heap_drop_kb"] == 4.0
    assert len(feature_vector(f)) == len(FEATURE_NAMES)


def test_duplicate_or_old_seq_is_replay():
    tr = DeviceTracker(5)
    tr.observe(tel(seq=5, uptime_s=100), 0)
    for seq in (5, 4):
        obs = tr.observe(tel(seq=seq, uptime_s=100), 1)
        assert obs.replay and obs.features is None


def test_reboot_then_replay_of_previous_boot():
    tr = DeviceTracker(5)
    old = tel(boot_id=1, seq=50, uptime_s=500)
    tr.observe(old, 0)
    obs = tr.observe(tel(boot_id=2, seq=1, uptime_s=10), 5)
    assert obs.reboot and obs.features is not None
    obs = tr.observe(tel(boot_id=1, seq=51, uptime_s=505), 6)  # captured pre-reboot traffic
    assert obs.replay


def test_replay_does_not_corrupt_state():
    tr = DeviceTracker(5)
    tr.observe(tel(seq=5, uptime_s=100), 0)
    tr.observe(tel(seq=3, uptime_s=90), 1)
    obs = tr.observe(tel(seq=6, uptime_s=105), 2)
    assert not obs.replay and obs.features["interval_s"] == 5


def test_counter_reset_never_negative():
    tr = DeviceTracker(5)
    tr.observe(tel(seq=1, uptime_s=100, wifi_reconnects=10), 0)
    obs = tr.observe(tel(seq=2, uptime_s=105, wifi_reconnects=0), 1)
    assert obs.features["wifi_reconnects"] == 0
