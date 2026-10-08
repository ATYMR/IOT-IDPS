"""End-to-end test against a real MQTT broker.

Runs only when IDPS_TEST_BROKER=host:port is set (CI starts Mosquitto).
A simulated device publishes signed telemetry; the live listener must detect
the flood and publish an authenticated QUARANTINE command back to it.
"""

import json
import os
import queue
import threading
import time
import uuid

import paho.mqtt.client as mqtt
import pytest
from conftest import DEVICE, KEY, signed

from idps import protocol
from idps.config import Settings
from idps.engine import IDPSEngine
from idps.mqtt_runtime import make_client, run_listener
from idps.response import AlertSink, DeviceCommander

BROKER = os.environ.get("IDPS_TEST_BROKER")
pytestmark = pytest.mark.skipif(not BROKER, reason="set IDPS_TEST_BROKER=host:port to run")


def wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_live_pipeline_quarantines_flooded_device(trained, tmp_path):
    host, port = BROKER.rsplit(":", 1)
    run_id = uuid.uuid4().hex[:8]
    prefix = f"idps-test/{run_id}"
    settings = Settings(mqtt_host=host, mqtt_port=int(port), topic_prefix=prefix, mode="prevent",
                        device_keys={DEVICE: KEY}, alert_log=tmp_path / "alerts.jsonl",
                        mqtt_client_id=f"idps-backend-{run_id}")
    client = make_client(settings)
    commander = DeviceCommander(lambda t, p: client.publish(t, p, qos=1), settings.device_keys, prefix)
    engine = IDPSEngine(settings, trained[0], AlertSink(settings.alert_log), commander)
    stop = threading.Event()
    listener = threading.Thread(target=run_listener, args=(settings, engine, client), daemon=True,
                                kwargs=dict(stop=stop, record_path=tmp_path / "rec.jsonl",
                                            record_label="normal", tick_s=0.2))
    listener.start()

    commands: queue.Queue[bytes] = queue.Queue()
    device = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"{DEVICE}-{run_id}")
    device.on_message = lambda c, u, m: commands.put(m.payload)
    device.connect(host, int(port))
    device.loop_start()
    try:
        device.subscribe(protocol.command_topic(DEVICE, prefix), qos=1)

        def publish(seq, **fields):
            topic, payload = signed(seq=seq, uptime_s=100 + 5 * seq, **fields)
            device.publish(topic.replace(protocol.DEFAULT_TOPIC_PREFIX, prefix, 1), payload, qos=1)

        # Keep sending a normal window until the listener has subscribed and seen it.
        assert wait_for(lambda: (publish(1), DEVICE in engine.tracker.known_devices())[1], timeout=15)
        for seq in range(2, 8):
            publish(seq, rx_msgs=150, auth_fail=25)

        body = json.loads(commands.get(timeout=15))
        assert body["cmd"] == "QUARANTINE"
        assert protocol.verify(KEY, protocol.command_canonical(DEVICE, body["ts"], "QUARANTINE"), body["mac"])
        alerts = (tmp_path / "alerts.jsonl").read_text().splitlines()
        assert any(json.loads(a)["category"] == "ml_anomaly" for a in alerts)
        assert (tmp_path / "rec.jsonl").read_text().count('"label": "normal"') >= 7
    finally:
        stop.set()
        listener.join(timeout=10)
        device.loop_stop()
        device.disconnect()
