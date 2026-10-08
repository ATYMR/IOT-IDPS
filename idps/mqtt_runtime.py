"""Live MQTT integration (paho-mqtt 2.x)."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt

from .config import Settings
from .engine import IDPSEngine

log = logging.getLogger(__name__)


def make_client(settings: Settings, client_id: str | None = None) -> mqtt.Client:
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id or settings.mqtt_client_id,
        protocol=mqtt.MQTTv311,
    )
    if settings.mqtt_username:
        client.username_pw_set(settings.mqtt_username, settings.mqtt_password)
    if settings.mqtt_tls:
        client.tls_set(ca_certs=settings.mqtt_ca_file)  # None -> system trust store
    elif settings.mqtt_username:
        log.warning("MQTT credentials will be sent in cleartext (IDPS_MQTT_TLS is off)")
    client.reconnect_delay_set(min_delay=1, max_delay=60)
    return client


def publish_once(settings: Settings, topic: str, payload: bytes, qos: int = 1, timeout: float = 10.0) -> None:
    client = make_client(settings, client_id=f"{settings.mqtt_client_id}-cli")
    client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=30)
    client.loop_start()
    try:
        info = client.publish(topic, payload, qos=qos)
        info.wait_for_publish(timeout=timeout)
        if not info.is_published():
            raise TimeoutError("broker did not acknowledge the publish")
    finally:
        client.disconnect()
        client.loop_stop()


class _Recorder:
    def __init__(self, path: Path, label: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")
        self._label = label

    def write(self, topic: str, payload: bytes) -> None:
        self._fh.write(json.dumps({"t": time.time(), "topic": topic,
                                   "payload": payload.decode("utf-8", errors="replace"),
                                   "label": self._label}) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


def run_listener(settings: Settings, engine: IDPSEngine, client: mqtt.Client,
                 record_path: Path | None = None, record_label: str = "unlabeled",
                 stop: threading.Event | None = None, tick_s: float = 1.0) -> None:
    """Subscribe to telemetry/status and feed the engine until ``stop`` is set."""
    stop = stop or threading.Event()
    lock = threading.Lock()  # engine is used from paho's thread and ours
    recorder = _Recorder(record_path, record_label) if record_path else None
    prefix = settings.topic_prefix

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code.is_failure:
            log.error("MQTT connect failed: %s", reason_code)
            return
        client.subscribe([(f"{prefix}/+/telemetry", 0), (f"{prefix}/+/status", 0)])
        log.info("connected to %s:%s, subscribed under %s/", settings.mqtt_host, settings.mqtt_port, prefix)

    def on_disconnect(client, userdata, flags, reason_code, properties):
        if not stop.is_set():
            log.warning("MQTT disconnected (%s); paho will reconnect", reason_code)

    def on_message(client, userdata, msg):
        try:
            if recorder and msg.topic.endswith("/telemetry"):
                recorder.write(msg.topic, msg.payload)
            with lock:
                engine.handle_message(msg.topic, msg.payload)
        except Exception:  # never let one bad message kill the network loop
            log.exception("error while handling message on %s", msg.topic)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    client.connect_async(settings.mqtt_host, settings.mqtt_port, keepalive=30)
    client.loop_start()
    try:
        while not stop.wait(tick_s):
            with lock:
                engine.tick()
    finally:
        client.disconnect()
        client.loop_stop()
        if recorder:
            recorder.close()
