import pytest

from idps.findings import Category, Finding
from idps.policy import Action, decide
from idps.risk import RULE_BASE_RISK, Severity, assess, severity_for


def finding(cat=Category.ML_ANOMALY, conf=0.9, device="esp32_01", ip=None):
    return Finding(cat, device, conf, "test", 0.0, ip)


@pytest.mark.parametrize("score,sev", [(0, "LOW"), (30, "LOW"), (31, "MEDIUM"), (60, "MEDIUM"),
                                       (61, "HIGH"), (80, "HIGH"), (81, "CRITICAL"), (100, "CRITICAL")])
def test_severity_bands(score, sev):
    assert severity_for(score).value == sev


def test_every_rule_category_has_base_risk():
    assert set(Category) - {Category.ML_ANOMALY} == set(RULE_BASE_RISK)


def test_ml_risk_tracks_confidence_and_persistence():
    assert assess(finding(conf=0.5)).score == 50
    assert assess(finding(conf=0.5), persistent=True).score == 65
    assert assess(finding(conf=5.0)).score == 100  # clamped


def test_detect_mode_never_acts():
    f = finding(conf=1.0, ip="10.0.0.9")
    actions = decide(f, assess(f, True), mode="detect", persistent=True, firewall_enabled=True)
    assert actions == [Action.LOG, Action.ALERT]


def test_low_severity_only_logged():
    f = finding(Category.DEVICE_REBOOT, conf=0.0)
    assert decide(f, assess(f), mode="prevent", persistent=True) == [Action.LOG]


def test_quarantine_needs_persistence():
    f = finding(conf=1.0)
    risk = assess(f)
    assert risk.severity is Severity.CRITICAL
    assert Action.QUARANTINE_DEVICE not in decide(f, risk, mode="prevent", persistent=False)
    assert Action.QUARANTINE_DEVICE in decide(f, risk, mode="prevent", persistent=True)


def test_no_duplicate_quarantine():
    f = finding(conf=1.0)
    actions = decide(f, assess(f), mode="prevent", persistent=True, already_quarantined=True)
    assert Action.QUARANTINE_DEVICE not in actions


def test_uncertain_detection_only_alerts():
    f = finding(conf=0.55)  # just above threshold
    actions = decide(f, assess(f), mode="prevent", persistent=False)
    assert actions == [Action.LOG, Action.ALERT]


def test_spoofed_traffic_never_quarantines_device():
    f = finding(Category.TELEMETRY_AUTH_FAILURE, conf=1.0)
    actions = decide(f, assess(f), mode="prevent", persistent=True)
    assert Action.QUARANTINE_DEVICE not in actions


def test_block_ip_requires_ip_firewall_and_critical():
    f = finding(conf=1.0, ip="203.0.113.5")
    assert Action.BLOCK_IP in decide(f, assess(f), mode="prevent", persistent=True, firewall_enabled=True)
    assert Action.BLOCK_IP not in decide(f, assess(f), mode="prevent", persistent=True, firewall_enabled=False)
    f2 = finding(conf=1.0)
    assert Action.BLOCK_IP not in decide(f2, assess(f2), mode="prevent", persistent=True, firewall_enabled=True)
