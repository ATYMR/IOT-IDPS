"""IDPS engine: message -> validation -> features -> rules + ML -> risk -> policy -> response."""

from __future__ import annotations

import logging
import subprocess
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from .config import Settings
from .detector import AnomalyDetector
from .features import DeviceTracker, feature_vector
from .findings import Category, Finding
from .policy import Action, decide
from .protocol import ProtocolError, decode_telemetry, parse_topic, verify
from .response import AlertSink, DeviceCommander, FirewallBlocker
from .risk import RiskAssessment, assess

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class EngineTuning:
    # Rule: device rejected at least this many commands in one report window.
    command_rejection_threshold: int = 3
    # Persistence: flagged in >= persistence_k of the last persistence_n windows.
    persistence_k: int = 3
    persistence_n: int = 5
    # Re-send QUARANTINE at most this often while the device has not yet
    # confirmed it (telemetry quarantined=1). Under a flood the device's parse
    # budget can drop our command, so retries matter; once confirmed, nothing
    # is re-sent.
    quarantine_cooldown_s: float = 30.0
    # Suppress identical (device, category) alerts within this many seconds.
    dedup_s: float = 30.0
    # Device considered offline after this many missed report intervals.
    offline_after_intervals: float = 3.0


@dataclass(frozen=True)
class Decision:
    finding: Finding
    risk: RiskAssessment
    actions: tuple[Action, ...]
    suppressed: bool = False


class IDPSEngine:
    def __init__(
        self,
        settings: Settings,
        detector: AnomalyDetector | None,
        alert_sink: AlertSink,
        commander: DeviceCommander | None = None,
        firewall: FirewallBlocker | None = None,
        tuning: EngineTuning | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.detector = detector
        self.alerts = alert_sink
        self.commander = commander
        self.firewall = firewall
        self.tuning = tuning or EngineTuning()
        self.clock = clock
        self.tracker = DeviceTracker(nominal_interval_s=settings.telemetry_interval_s)
        self._history: dict[str, deque[bool]] = {}
        self._last_quarantine: dict[str, float] = {}
        self._last_emitted: dict[tuple[str | None, Category], float] = {}
        self._offline: set[str] = set()
        if detector is None:
            log.warning("no anomaly model loaded: running in rules-only (degraded) mode")

    # ------------------------------------------------------------ input

    def handle_message(self, topic: str, payload: bytes, source_ip: str | None = None) -> list[Decision]:
        now = self.clock()
        try:
            device_id, kind = parse_topic(topic, self.settings.topic_prefix)
        except ProtocolError as exc:
            return [self._process(Finding(Category.MALFORMED, None, 0.0, str(exc), now, source_ip))]

        if kind == "status":
            # Status/LWT messages are NOT authenticated; treat as a hint only.
            if payload.strip() == b"offline" and device_id in self.settings.device_keys:
                return [self._mark_offline(device_id, now, "device reported offline (MQTT last will)")]
            return []
        if kind != "telemetry":
            return []

        key = self.settings.device_keys.get(device_id)
        if key is None:
            return [self._process(Finding(Category.UNKNOWN_DEVICE, device_id, 0.0,
                                          "telemetry from unregistered device", now, source_ip))]
        try:
            telemetry = decode_telemetry(payload, topic_device_id=device_id)
        except ProtocolError as exc:
            return [self._process(Finding(Category.MALFORMED, device_id, 0.5, str(exc), now, source_ip))]
        if not verify(key, telemetry.canonical(), telemetry.mac):
            return [self._process(Finding(Category.TELEMETRY_AUTH_FAILURE, device_id, 1.0,
                                          "telemetry MAC verification failed (spoofed or corrupted)",
                                          now, source_ip))]

        obs = self.tracker.observe(telemetry, now)
        self._offline.discard(device_id)
        if obs.replay:
            return [self._process(Finding(Category.REPLAY, device_id, 1.0, obs.replay_reason, now, source_ip))]

        findings: list[Finding] = []
        if obs.reboot:
            findings.append(Finding(Category.DEVICE_REBOOT, device_id, 0.0, "device rebooted", now))

        assert obs.features is not None
        if telemetry.auth_fail >= self.tuning.command_rejection_threshold:
            findings.append(Finding(
                Category.COMMAND_REJECTIONS, device_id, min(1.0, telemetry.auth_fail / 20.0),
                f"device rejected {telemetry.auth_fail} commands (forged/stale/malformed)",
                now, source_ip, obs.features))

        if self.detector is not None:
            vector = feature_vector(obs.features)
            score = float(self.detector.score([vector])[0])
            if score > self.detector.threshold:
                conf = float(self.detector.confidence([score])[0])
                detail = f"anomaly score {score:.2f} > {self.detector.threshold:.2f}; " + self.detector.explain(vector)
                findings.append(Finding(Category.ML_ANOMALY, device_id, conf, detail,
                                        now, source_ip, obs.features))

        history = self._history.setdefault(device_id, deque(maxlen=self.tuning.persistence_n))
        history.append(any(f.device_attributable for f in findings))
        return [self._process(f) for f in findings]

    def tick(self) -> list[Decision]:
        """Periodic housekeeping: offline detection and firewall expiry."""
        now = self.clock()
        decisions = []
        limit = self.tuning.offline_after_intervals * self.settings.telemetry_interval_s
        for device_id in self.tracker.known_devices():
            last = self.tracker.last_seen(device_id)
            if last is not None and now - last > limit and device_id not in self._offline:
                decisions.append(self._mark_offline(device_id, now, f"no telemetry for {now - last:.0f}s"))
        if self.firewall is not None:
            self.firewall.expire(now)
        # Bound memory: forget de-dup entries that can no longer suppress anything.
        self._last_emitted = {k: t for k, t in self._last_emitted.items() if now - t < self.tuning.dedup_s}
        return decisions

    # ------------------------------------------------------------ internals

    def _persistent(self, device_id: str | None) -> bool:
        history = self._history.get(device_id or "")
        return bool(history) and sum(history) >= self.tuning.persistence_k

    def _mark_offline(self, device_id: str, now: float, detail: str) -> Decision:
        self._offline.add(device_id)
        return self._process(Finding(Category.DEVICE_OFFLINE, device_id, 0.0, detail, now))

    def _process(self, finding: Finding) -> Decision:
        persistent = finding.device_attributable and self._persistent(finding.device_id)
        risk = assess(finding, persistent=persistent)
        actions = decide(
            finding, risk,
            mode=self.settings.mode,
            persistent=persistent,
            already_quarantined=bool(finding.device_id) and self._quarantine_active(finding.device_id),
            firewall_enabled=self.firewall is not None,
        )
        executed = self._execute(finding, actions)

        # Unregistered ids come straight from the topic, so an attacker can
        # invent unlimited ones: de-duplicate those as a single source.
        registered = finding.device_id in self.settings.device_keys
        key = (finding.device_id if registered else None, finding.category)
        last = self._last_emitted.get(key)
        suppressed = (Action.QUARANTINE_DEVICE not in executed and last is not None
                      and finding.timestamp - last < self.tuning.dedup_s)
        if not suppressed:
            self._last_emitted[key] = finding.timestamp
            record = finding.to_dict()
            record.update(risk_score=risk.score, severity=risk.severity.value,
                          actions=[a.value for a in executed], mode=self.settings.mode)
            self.alerts.emit(record)
        return Decision(finding, risk, tuple(executed), suppressed)

    def _quarantine_active(self, device_id: str) -> bool:
        if self.tracker.is_quarantined(device_id):
            return True
        sent = self._last_quarantine.get(device_id)
        return sent is not None and self.clock() - sent < self.tuning.quarantine_cooldown_s

    def _execute(self, finding: Finding, actions: list[Action]) -> list[Action]:
        executed = []
        for action in actions:
            if action is Action.QUARANTINE_DEVICE:
                if self.commander is None:
                    log.error("policy requested quarantine but no command channel is configured")
                    continue
                try:
                    self.commander.send(finding.device_id, "QUARANTINE")
                except Exception as exc:  # broker down, missing key, ...
                    log.error("quarantine of %s failed: %s", finding.device_id, exc)
                    continue
                self._last_quarantine[finding.device_id] = finding.timestamp
            elif action is Action.BLOCK_IP:
                try:
                    self.firewall.block(finding.source_ip, finding.timestamp)
                except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
                    log.error("block of %s failed: %s", finding.source_ip, exc)
                    continue
            executed.append(action)
        return executed
