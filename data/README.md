# Data

Nothing in this directory is committed except this file.

## Synthetic data (default)

```bash
python -m idps generate-data --seed 42          # -> data/synthetic/telemetry.jsonl
```

Deterministic for a given seed. ~12,000 records, ~4 MB. See
`docs/evaluation.md` for what it models and its limitations.

## Real data (recommended for any claim about performance)

Record telemetry from your own devices through the live listener:

```bash
python -m idps listen --record data/raw/baseline.jsonl --label normal
```

To label attack runs, record each authorised lab experiment into its own file
with a matching `--label` (e.g. `cmd_flood`), then concatenate the files in
time order.

## Format

JSON Lines, one MQTT message per line:

```json
{"t": 1733000000.12, "topic": "idps/v1/esp32_01/telemetry", "payload": "{\"v\":1,...}", "label": "normal"}
```

`t` is the receive time (seconds). `payload` is the exact message body.
`label` is `normal`, an attack name, or `unlabeled`. Training and evaluation
replay these records through the same validation and feature code as the live
system. Invalid records are counted and skipped.

Recorded payloads contain device identifiers and MACs, but no keys.
