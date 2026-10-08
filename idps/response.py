"""Response actuators: alert sink, authenticated device commands, firewall."""

from __future__ import annotations

import ipaddress
import json
import logging
import platform
import subprocess
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from .protocol import command_topic, encode_command

log = logging.getLogger(__name__)


class AlertSink:
    """Append-only JSON Lines alert log (one record per decision)."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, record: dict) -> None:
        line = json.dumps(record, sort_keys=True, default=str)
        level = logging.WARNING if "ALERT" in record.get("actions", []) else logging.INFO
        log.log(level, "%s %s device=%s risk=%s actions=%s | %s",
                record.get("severity"), record.get("category"), record.get("device_id"),
                record.get("risk_score"), ",".join(record.get("actions", [])), record.get("detail"))
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")


class DeviceCommander:
    """Publishes HMAC-authenticated commands to devices over MQTT."""

    def __init__(
        self,
        publish: Callable[[str, bytes], None],
        device_keys: dict[str, bytes],
        topic_prefix: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._publish = publish
        self._keys = device_keys
        self._prefix = topic_prefix
        self._clock = clock
        self._last_ts = 0

    def _next_ts(self) -> int:
        # Devices reject any timestamp <= the last one they accepted, so keep
        # it strictly increasing even if the wall clock steps backwards.
        self._last_ts = max(int(self._clock() * 1000), self._last_ts + 1)
        return self._last_ts

    def send(self, device_id: str, command: str) -> bytes:
        key = self._keys.get(device_id)
        if key is None:
            raise KeyError(f"no key configured for device {device_id!r}")
        payload = encode_command(device_id, command, self._next_ts(), key)
        self._publish(command_topic(device_id, self._prefix), payload)
        log.warning("sent %s to %s", command, device_id)
        return payload


def validate_block_target(ip: str, never_block: Iterable[str] = ()) -> str:
    """Return the normalised IP or raise ValueError. Never shells out."""
    addr = ipaddress.ip_address(ip.strip())
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
        raise ValueError(f"refusing to block special address {addr}")
    if str(addr) in {str(ipaddress.ip_address(x)) for x in never_block}:
        raise ValueError(f"{addr} is on the never-block list")
    return str(addr)


class FirewallBlocker:
    """Temporary host-firewall blocks (iptables on Linux, netsh on Windows).

    EXPERIMENTAL: no implemented event source supplies attacker IPs yet (MQTT
    telemetry does not carry them), so this is only reachable from findings
    that set ``source_ip``. Dry-run by default; real blocking needs root/admin.
    Expired blocks are removed by :meth:`expire`, which the engine calls on
    every tick - nothing here sleeps.
    """

    def __init__(self, dry_run: bool = True, duration_s: int = 300,
                 never_block: Iterable[str] = (), system: str | None = None,
                 runner: Callable[[list[str]], None] | None = None) -> None:
        self.dry_run = dry_run
        self.duration_s = duration_s
        self.never_block = tuple(never_block)
        self.system = system or platform.system()
        self._runner = runner or self._run
        self.active: dict[str, float] = {}  # ip -> expiry time

    def _commands(self, ip: str, add: bool) -> list[str]:
        if self.system == "Windows":
            if add:
                return ["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=IDPS_BLOCK_{ip}", "dir=in", "action=block", f"remoteip={ip}"]
            return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=IDPS_BLOCK_{ip}"]
        if self.system == "Linux":
            return ["iptables", "-I" if add else "-D", "INPUT", "-s", ip, "-j", "DROP",
                    "-m", "comment", "--comment", "idps"]
        raise RuntimeError(f"firewall blocking is not supported on {self.system}")

    @staticmethod
    def _run(cmd: list[str]) -> None:
        subprocess.run(cmd, check=True, timeout=15, capture_output=True)  # no shell

    def block(self, ip: str, now: float) -> list[str]:
        ip = validate_block_target(ip, self.never_block)
        cmd = self._commands(ip, add=True)
        if ip not in self.active:
            if self.dry_run:
                log.warning("[dry-run] would run: %s", " ".join(cmd))
            else:
                self._runner(cmd)
        self.active[ip] = now + self.duration_s
        return cmd

    def expire(self, now: float) -> list[str]:
        released = [ip for ip, until in self.active.items() if until <= now]
        for ip in released:
            cmd = self._commands(ip, add=False)
            if self.dry_run:
                log.info("[dry-run] would run: %s", " ".join(cmd))
            else:
                try:
                    self._runner(cmd)
                except (subprocess.SubprocessError, OSError) as exc:
                    log.error("failed to remove block for %s: %s", ip, exc)
                    continue
            del self.active[ip]
        return released
