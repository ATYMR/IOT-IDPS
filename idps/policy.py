"""Policy: decide which response actions a finding warrants.

Safety rules (deliberately conservative, to limit damage from false positives):

* ``detect`` mode (the default) never takes automated action - IDS only.
* Automated quarantine requires ``prevent`` mode, HIGH/CRITICAL severity,
  a finding attributable to an authenticated device, and *persistence*
  (the device was flagged in several recent windows). A single anomalous
  window only ever produces an alert.
* IP blocking additionally needs CRITICAL severity, a source IP on the
  finding and the firewall responder explicitly enabled.
"""

from __future__ import annotations

from enum import Enum

from .findings import Finding
from .risk import RiskAssessment, Severity


class Action(str, Enum):
    LOG = "LOG"
    ALERT = "ALERT"
    QUARANTINE_DEVICE = "QUARANTINE_DEVICE"
    BLOCK_IP = "BLOCK_IP"


def decide(
    finding: Finding,
    risk: RiskAssessment,
    *,
    mode: str,
    persistent: bool,
    already_quarantined: bool = False,
    firewall_enabled: bool = False,
) -> list[Action]:
    actions = [Action.LOG]
    if risk.severity is Severity.LOW:
        return actions
    actions.append(Action.ALERT)

    if mode != "prevent" or risk.severity not in (Severity.HIGH, Severity.CRITICAL):
        return actions

    if finding.device_attributable and persistent and not already_quarantined:
        actions.append(Action.QUARANTINE_DEVICE)
    if risk.severity is Severity.CRITICAL and finding.source_ip and firewall_enabled:
        actions.append(Action.BLOCK_IP)
    return actions
