"""Command-line interface: ``python -m idps <command>``."""

from __future__ import annotations

import argparse
import json
import logging
import secrets
import sys
import time
from collections import Counter
from pathlib import Path

from . import __version__
from .config import ConfigError, Settings, load_settings
from .detector import KINDS
from .protocol import COMMANDS, DEVICE_ID_RE

log = logging.getLogger("idps")

DEFAULT_DATA = Path("data/synthetic/telemetry.jsonl")
DEFAULT_MODEL = Path("models/isolation_forest.joblib")


def cmd_gen_key(args) -> int:
    if not DEVICE_ID_RE.match(args.device_id):
        print("invalid device id", file=sys.stderr)
        return 2
    key = secrets.token_hex(32)
    print(f"# backend .env (append to IDPS_DEVICE_KEYS, comma-separated):\n{args.device_id}:{key}\n")
    print(f'# firmware include/secrets.h:\n#define IDPS_DEVICE_ID "{args.device_id}"\n'
          f'#define IDPS_DEVICE_KEY_HEX "{key}"')
    return 0


def cmd_generate(args) -> int:
    from .synthetic import generate, save_jsonl

    records = generate(n_windows=args.windows, seed=args.seed)
    save_jsonl(records, args.out)
    labels = Counter(r.label for r in records)
    print(f"wrote {len(records)} SYNTHETIC records to {args.out}: {dict(labels)}")
    return 0


def _write_report(report: dict, report_dir: Path, name: str) -> None:
    from .evaluation import report_markdown

    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / f"{name}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if "per_attack_recall" in report and "episodes" in report:
        (report_dir / f"{name}.md").write_text(report_markdown(report) + "\n", encoding="utf-8")


def cmd_train(args) -> int:
    from .evaluation import report_markdown, train_and_evaluate
    from .synthetic import load_jsonl

    if not args.data.is_file():
        print(f"dataset not found: {args.data} (run `python -m idps generate-data` first)", file=sys.stderr)
        return 2
    detector, report = train_and_evaluate(load_jsonl(args.data), target_fpr=args.target_fpr,
                                          n_estimators=args.n_estimators, seed=args.seed, kind=args.detector)
    detector.metadata["dataset"] = str(args.data)
    detector.save(args.model)
    _write_report(report, args.report_dir, "train_eval")
    print(f"model saved to {args.model} (threshold={detector.threshold:.4f})")
    if "episodes" in report:
        print(report_markdown(report))
    else:
        print(report["note"], json.dumps(report["detectors"]))
    print(f"latency: {report['latency']}")
    return 0


def cmd_benchmark(args) -> int:
    from .evaluation import benchmark, benchmark_markdown

    result = benchmark(list(range(args.first_seed, args.first_seed + args.seeds)), n_windows=args.windows,
                       target_fpr=args.target_fpr, n_estimators=args.n_estimators)
    args.report_dir.mkdir(parents=True, exist_ok=True)
    (args.report_dir / "benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    text = benchmark_markdown(result)
    (args.report_dir / "benchmark.md").write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


def cmd_evaluate(args) -> int:
    from .detector import AnomalyDetector
    from .evaluation import evaluate_model
    from .synthetic import load_jsonl

    report = evaluate_model(AnomalyDetector.load(args.model), load_jsonl(args.data))
    _write_report(report, args.report_dir, "evaluate")
    print(json.dumps(report, indent=2))
    return 0


def cmd_simulate(args) -> int:
    """Offline end-to-end demo: synthetic devices -> full engine -> dry-run responses."""
    from .engine import IDPSEngine
    from .evaluation import train_and_evaluate
    from .response import AlertSink, DeviceCommander
    from .synthetic import demo_keys, generate

    records = generate(n_windows=args.windows, seed=args.seed)
    split = int(len(records) * 0.75)
    detector, _ = train_and_evaluate(records, seed=args.seed, compare=False)  # normal prefix only

    clock = {"now": 0.0}
    sent: list[tuple[str, bytes]] = []
    settings = Settings(mode=args.mode, device_keys=demo_keys(args.seed), alert_log=args.alert_log)
    commander = DeviceCommander(lambda topic, payload: sent.append((topic, payload)),
                                settings.device_keys, settings.topic_prefix, clock=lambda: clock["now"])
    engine = IDPSEngine(settings, detector, AlertSink(args.alert_log), commander, clock=lambda: clock["now"])

    decisions, quarantine_labels = [], Counter()
    for r in records[split:]:  # replay only the part the model was not trained on
        clock["now"] = r.t
        new = engine.handle_message(r.topic, r.payload)
        decisions += new
        if any(a.value == "QUARANTINE_DEVICE" for d in new for a in d.actions):
            quarantine_labels[r.label] += 1
    alerts = [d for d in decisions if "ALERT" in [a.value for a in d.actions]]
    print(f"\nreplayed {len(records) - split} telemetry messages in '{args.mode}' mode")
    print(f"findings: {dict(Counter(d.finding.category.value for d in decisions))}")
    print(f"alerts:   {len(alerts)} ({sum(d.suppressed for d in alerts)} de-duplicated)")
    print(f"severity: {dict(Counter(d.risk.severity.value for d in decisions))}")
    print(f"commands published (dry-run, not sent to any broker): {len(sent)}")
    print(f"quarantines by ground-truth label of the triggering window: {dict(quarantine_labels)}")
    for topic, payload in sent[:3]:
        print(f"  {topic} {payload.decode()}")
    return 0


def _build_live_engine(settings: Settings):
    from .detector import AnomalyDetector, ModelError
    from .engine import IDPSEngine
    from .mqtt_runtime import make_client
    from .response import AlertSink, DeviceCommander, FirewallBlocker

    try:
        detector = AnomalyDetector.load(settings.model_path)
    except ModelError as exc:
        log.warning("%s", exc)
        detector = None
    client = make_client(settings)
    commander = None
    if settings.mode == "prevent":
        commander = DeviceCommander(lambda t, p: client.publish(t, p, qos=1),
                                    settings.device_keys, settings.topic_prefix)
    firewall = None
    if settings.firewall_enabled:
        firewall = FirewallBlocker(dry_run=settings.firewall_dry_run, never_block=[])
    engine = IDPSEngine(settings, detector, AlertSink(settings.alert_log), commander, firewall)
    return engine, client


def cmd_listen(args) -> int:
    from .mqtt_runtime import run_listener

    settings = load_settings(args.env_file)
    if not settings.device_keys:
        print("IDPS_DEVICE_KEYS is empty: every message would be rejected. See .env.example.",
              file=sys.stderr)
        return 2
    engine, client = _build_live_engine(settings)
    log.info("IDPS listening (mode=%s, devices=%s)", settings.mode, sorted(settings.device_keys))
    try:
        run_listener(settings, engine, client, record_path=args.record, record_label=args.label)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_send(args) -> int:
    from .mqtt_runtime import publish_once
    from .protocol import command_topic, encode_command

    settings = load_settings(args.env_file)
    key = settings.device_keys.get(args.device_id)
    if key is None:
        print(f"no key for {args.device_id} in IDPS_DEVICE_KEYS", file=sys.stderr)
        return 2
    payload = encode_command(args.device_id, args.command, int(time.time() * 1000), key)
    publish_once(settings, command_topic(args.device_id, settings.topic_prefix), payload)
    print(f"sent {args.command} to {args.device_id}")
    return 0


def cmd_check_config(args) -> int:
    settings = load_settings(args.env_file)
    print(f"broker:   {settings.mqtt_host}:{settings.mqtt_port} tls={settings.mqtt_tls} "
          f"auth={'yes' if settings.mqtt_username else 'no'}")
    print(f"mode:     {settings.mode}")
    print(f"devices:  {sorted(settings.device_keys) or 'NONE'}")
    print(f"model:    {settings.model_path} ({'present' if settings.model_path.is_file() else 'missing'})")
    problems = []
    if not settings.device_keys:
        problems.append("no device keys configured")
    if not settings.mqtt_tls:
        problems.append("TLS disabled: traffic (incl. credentials) is cleartext")
    if not settings.mqtt_username:
        problems.append("no broker authentication configured")
    for p in problems:
        print(f"warning:  {p}")
    return 1 if not settings.device_keys else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="idps", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("gen-key", help="generate a per-device HMAC key")
    s.add_argument("--device-id", default="esp32_01")
    s.set_defaults(func=cmd_gen_key)

    s = sub.add_parser("generate-data", help="write a synthetic labelled telemetry dataset")
    s.add_argument("--out", type=Path, default=DEFAULT_DATA)
    s.add_argument("--windows", type=int, default=4000, help="report windows per device")
    s.add_argument("--seed", type=int, default=42)
    s.set_defaults(func=cmd_generate)

    s = sub.add_parser("train", help="train + evaluate the anomaly model")
    s.add_argument("--data", type=Path, default=DEFAULT_DATA)
    s.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    s.add_argument("--report-dir", type=Path, default=Path("reports"))
    s.add_argument("--target-fpr", type=float, default=0.01)
    s.add_argument("--n-estimators", type=int, default=200)
    s.add_argument("--seed", type=int, default=42)
    s.add_argument("--detector", choices=sorted(KINDS), default="ensemble")
    s.set_defaults(func=cmd_train)

    s = sub.add_parser("benchmark", help="multi-seed comparison of detector kinds on synthetic data")
    s.add_argument("--seeds", type=int, default=10)
    s.add_argument("--first-seed", type=int, default=0)
    s.add_argument("--windows", type=int, default=4000)
    s.add_argument("--target-fpr", type=float, default=0.01)
    s.add_argument("--n-estimators", type=int, default=200)
    s.add_argument("--report-dir", type=Path, default=Path("reports"))
    s.set_defaults(func=cmd_benchmark)

    s = sub.add_parser("evaluate", help="evaluate a saved model on a labelled dataset")
    s.add_argument("--data", type=Path, required=True)
    s.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    s.add_argument("--report-dir", type=Path, default=Path("reports"))
    s.set_defaults(func=cmd_evaluate)

    s = sub.add_parser("simulate", help="offline end-to-end demo on synthetic devices")
    s.add_argument("--mode", choices=["detect", "prevent"], default="prevent")
    s.add_argument("--windows", type=int, default=4000)
    s.add_argument("--seed", type=int, default=42)
    s.add_argument("--alert-log", type=Path, default=None)
    s.set_defaults(func=cmd_simulate)

    for name, func, help_ in (("listen", cmd_listen, "run the live IDPS against an MQTT broker"),
                              ("check-config", cmd_check_config, "validate .env configuration")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("--env-file", default=".env")
        s.set_defaults(func=func)
        if name == "listen":
            s.add_argument("--record", type=Path, help="append raw telemetry to this JSONL file")
            s.add_argument("--label", default="unlabeled", help="label for recorded windows")

    s = sub.add_parser("send-command", help="send an authenticated command to a device")
    s.add_argument("device_id")
    s.add_argument("command", choices=COMMANDS)
    s.add_argument("--env-file", default=".env")
    s.set_defaults(func=cmd_send)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
