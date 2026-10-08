import json
import re

import pytest

from idps.cli import main
from idps.config import parse_device_keys


def test_gen_key_output_is_usable(capsys):
    assert main(["gen-key", "--device-id", "lab_node"]) == 0
    out = capsys.readouterr().out
    pair = re.search(r"^(lab_node:[0-9a-f]{64})$", out, re.M).group(1)
    assert list(parse_device_keys(pair)) == ["lab_node"]
    assert '#define IDPS_DEVICE_KEY_HEX "' in out


def test_gen_key_rejects_bad_id():
    assert main(["gen-key", "--device-id", "bad id"]) == 2


def test_generate_train_evaluate_roundtrip(tmp_path, capsys):
    data, model, reports = tmp_path / "d.jsonl", tmp_path / "m.joblib", tmp_path / "r"
    assert main(["generate-data", "--windows", "900", "--seed", "3", "--out", str(data)]) == 0
    assert main(["train", "--data", str(data), "--model", str(model), "--report-dir", str(reports),
                 "--n-estimators", "30", "--detector", "zscore"]) == 0
    assert model.is_file() and (reports / "train_eval.md").is_file()
    report = json.loads((reports / "train_eval.json").read_text())
    assert report["config"]["kind"] == "zscore"
    assert main(["evaluate", "--data", str(data), "--model", str(model), "--report-dir", str(reports)]) == 0
    assert "zscore" in json.loads((reports / "evaluate.json").read_text())["detectors"]


def test_train_missing_dataset(tmp_path):
    assert main(["train", "--data", str(tmp_path / "nope.jsonl")]) == 2


def test_simulate_runs_offline(capsys):
    assert main(["simulate", "--windows", "1200", "--seed", "5", "--mode", "detect"]) == 0
    out = capsys.readouterr().out
    assert "commands published (dry-run, not sent to any broker): 0" in out


def test_check_config(tmp_path, monkeypatch, capsys):
    for var in ("IDPS_DEVICE_KEYS", "IDPS_MODE", "IDPS_MQTT_TLS"):
        monkeypatch.delenv(var, raising=False)
    env = tmp_path / ".env"
    env.write_text(f"IDPS_DEVICE_KEYS=esp32_01:{'ab' * 32}\nIDPS_MODE=prevent\n")
    assert main(["check-config", "--env-file", str(env)]) == 0
    out = capsys.readouterr().out
    assert "esp32_01" in out and "prevent" in out and "TLS disabled" in out
    assert "ab" * 32 not in out  # never print keys


def test_invalid_config_reports_error(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("IDPS_MODE", raising=False)
    env = tmp_path / ".env"
    env.write_text("IDPS_MODE=attack\n")
    assert main(["check-config", "--env-file", str(env)]) == 2
    assert "configuration error" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["listen"], ["send-command", "esp32_01", "PING"]])
def test_live_commands_refuse_without_keys(tmp_path, monkeypatch, argv):
    monkeypatch.delenv("IDPS_DEVICE_KEYS", raising=False)
    assert main([*argv, "--env-file", str(tmp_path / "missing.env")]) == 2
