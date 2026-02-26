#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


METRIC_CANDIDATES = {
    "mean": ["mean_ms", "mean", "avg_ms", "avg", "average_ms", "average"],
    "median": ["median_ms", "median", "p50_ms", "p50"],
    "p95": ["p95_ms", "p95"],
    "min": ["min_ms", "min"],
    "max": ["max_ms", "max"],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize mobench CI artifacts.")
    parser.add_argument("--ios-dir", required=True)
    parser.add_argument("--android-dir", required=True)
    parser.add_argument("--ios-result", required=True)
    parser.add_argument("--android-result", required=True)
    parser.add_argument("--platforms", required=True)
    parser.add_argument("--proof-scope", required=True)
    parser.add_argument("--modes", required=True)
    parser.add_argument("--device-profile", required=True)
    parser.add_argument("--mobench-ref", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--pr-number", default="")
    parser.add_argument("--requested-by", default="")
    parser.add_argument("--request-command", default="")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def try_number(value: str) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def parse_csv_row(csv_path: Path) -> dict[str, str]:
    try:
        raw = csv_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    if not raw.strip():
        return {}

    sample = raw[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel

    reader = csv.DictReader(raw.splitlines(), dialect=dialect)
    for row in reader:
        return {k or "": v or "" for k, v in row.items()}
    return {}


def extract_metrics(row: dict[str, str]) -> dict[str, float]:
    if not row:
        return {}

    normalized = {normalize_key(k): v for k, v in row.items()}
    metrics: dict[str, float] = {}

    for label, candidates in METRIC_CANDIDATES.items():
        for key in candidates:
            if key in normalized:
                value = try_number(normalized[key])
                if value is not None:
                    metrics[label] = value
                    break

    if metrics:
        return metrics

    excluded = {"n", "count", "iteration", "iterations", "sample", "samples", "index"}
    for key, value in normalized.items():
        if key in excluded:
            continue
        num = try_number(value)
        if num is None:
            continue
        metrics[key] = num
        if len(metrics) >= 3:
            break
    return metrics


def infer_scope_and_mode(stem: str) -> tuple[str, str]:
    scope = "unknown"
    mode = "unknown"
    if stem.startswith("nullifier-"):
        scope = "pi2"
    elif stem.startswith("query-"):
        scope = "pi1"

    parts = stem.split("-")
    if len(parts) >= 2:
        mode = parts[-1]
    return scope, mode


def parse_device_from_toml(root: Path, platform: str) -> str:
    if tomllib is None:
        return "unknown (tomllib unavailable)"

    patterns = [
        f"**/bench-config.{platform}.runtime.toml",
        f"**/bench-config.{platform}.runtime.*.toml",
    ]
    tomls: list[Path] = []
    for pattern in patterns:
        tomls.extend(sorted(root.glob(pattern)))

    for cfg in tomls:
        try:
            data = tomllib.loads(cfg.read_text(encoding="utf-8"))
        except Exception:
            continue
        bs = data.get("browserstack")
        if not isinstance(bs, dict):
            continue
        devices = bs.get("devices")
        if not isinstance(devices, list) or not devices:
            continue
        first = devices[0]
        if not isinstance(first, dict):
            continue
        name = str(first.get("name", "")).strip()
        os_version = str(first.get("os_version", "")).strip()
        if name and os_version:
            return f"{name} (os {os_version})"
        if name:
            return name
    return "unknown"


def status_sentence(ios_result: str, android_result: str) -> str:
    statuses = {"ios": ios_result, "android": android_result}
    results = list(statuses.values())
    if all(s == "skipped" for s in results):
        return "No benchmarks ran because both platform jobs were skipped."
    if all(s == "success" or s == "skipped" for s in results):
        if any(s == "success" for s in results):
            return "Benchmark run completed successfully for all requested platforms."
        return "Benchmark run completed with no executed platforms."
    if any(s == "success" for s in results):
        return "Benchmark run completed with partial results due to at least one non-success platform job."
    return "Benchmark run failed before producing complete platform results."


def status_label(result: str) -> str:
    value = (result or "").strip().lower()
    if value == "success":
        return "ok"
    if value in {"failure", "failed"}:
        return "failed"
    if value == "cancelled":
        return "cancelled"
    if value == "skipped":
        return "skipped"
    if value == "in_progress":
        return "in_progress"
    return value or "unknown"


def fmt_metric(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}"


def summarize_platform(root: Path, platform: str) -> tuple[list[dict[str, object]], list[str], int]:
    csv_files = sorted(root.glob("**/*.csv"))
    entries: list[dict[str, object]] = []
    lines: list[str] = []
    count = 0

    for csv_file in csv_files:
        count += 1
        stem = csv_file.stem
        scope, mode = infer_scope_and_mode(stem)
        row = parse_csv_row(csv_file)
        metrics = extract_metrics(row)

        if metrics:
            metric_parts = [f"{k}={v:.3f}" for k, v in metrics.items()]
            metric_text = ", ".join(metric_parts)
        else:
            metric_text = "no numeric metrics parsed"

        entries.append(
            {
                "stem": stem,
                "scope": scope,
                "mode": mode,
                "metrics": metrics,
            }
        )
        lines.append(
            f"- `{stem}` ({scope}, {mode}): {metric_text}"
        )

    if count == 0:
        lines.append(f"- No CSV summaries found under `{root}`.")
    return entries, lines, count


def aggregate_metric(entries: list[dict[str, object]], metric_name: str) -> float | None:
    values: list[float] = []
    for entry in entries:
        metrics = entry.get("metrics")
        if not isinstance(metrics, dict):
            continue
        value = metrics.get(metric_name)
        if isinstance(value, (int, float)):
            values.append(float(value))
    if not values:
        return None
    return sum(values) / len(values)


def slowest_entry(entries: list[dict[str, object]]) -> str:
    best_name = "n/a"
    best_value: float | None = None
    best_metric = ""

    for entry in entries:
        stem = str(entry.get("stem", "unknown"))
        metrics = entry.get("metrics")
        if not isinstance(metrics, dict):
            continue

        candidate_metric = ""
        candidate_value: float | None = None
        if isinstance(metrics.get("mean"), (int, float)):
            candidate_metric = "mean"
            candidate_value = float(metrics["mean"])
        elif isinstance(metrics.get("median"), (int, float)):
            candidate_metric = "median"
            candidate_value = float(metrics["median"])

        if candidate_value is None:
            continue
        if best_value is None or candidate_value > best_value:
            best_value = candidate_value
            best_name = stem
            best_metric = candidate_metric

    if best_value is None:
        return "n/a"
    return f"`{best_name}` ({best_metric}={best_value:.3f})"


def build_markdown(args: argparse.Namespace) -> str:
    ios_dir = Path(args.ios_dir)
    android_dir = Path(args.android_dir)

    ios_device = parse_device_from_toml(ios_dir, "ios")
    android_device = parse_device_from_toml(android_dir, "android")

    ios_entries, ios_lines, ios_count = summarize_platform(ios_dir, "ios")
    android_entries, android_lines, android_count = summarize_platform(android_dir, "android")

    lines: list[str] = []
    lines.append("## Mobile Bench CI Summary")
    lines.append("")
    lines.append(status_sentence(args.ios_result, args.android_result))
    lines.append("")
    lines.append("### At-a-glance scorecard")
    lines.append("| Platform | Status | Device | Parsed CSV files | Avg mean | Avg median | Slowest benchmark |")
    lines.append("| --- | --- | --- | ---: | ---: | ---: | --- |")
    lines.append(
        "| iOS | "
        f"`{status_label(args.ios_result)}` | "
        f"{ios_device} | "
        f"{ios_count} | "
        f"{fmt_metric(aggregate_metric(ios_entries, 'mean'))} | "
        f"{fmt_metric(aggregate_metric(ios_entries, 'median'))} | "
        f"{slowest_entry(ios_entries)} |"
    )
    lines.append(
        "| Android | "
        f"`{status_label(args.android_result)}` | "
        f"{android_device} | "
        f"{android_count} | "
        f"{fmt_metric(aggregate_metric(android_entries, 'mean'))} | "
        f"{fmt_metric(aggregate_metric(android_entries, 'median'))} | "
        f"{slowest_entry(android_entries)} |"
    )
    lines.append("")
    lines.append(
        "All latency-style metrics above are reported as raw values parsed from mobench CSV summaries."
    )
    lines.append("")
    lines.append("### Run metadata")
    lines.append(f"- Run: [View workflow run]({args.run_url})")
    lines.append(f"- Mobench ref: `{args.mobench_ref}`")
    lines.append(
        f"- Inputs: `platforms={args.platforms}`, `proof_scope={args.proof_scope}`, "
        f"`modes={args.modes}`, `device_profile={args.device_profile}`"
    )
    if args.pr_number:
        lines.append(f"- PR: `#{args.pr_number}`")
    if args.requested_by:
        lines.append(f"- Requested by: `{args.requested_by}`")
    if args.request_command:
        lines.append(f"- Command: `{args.request_command}`")
    lines.append("")

    lines.append("### Platform status")
    lines.append(f"- iOS job: `{args.ios_result}`")
    lines.append(f"- Android job: `{args.android_result}`")
    lines.append("")

    lines.append("### Device selection")
    lines.append(f"- iOS: {ios_device}")
    lines.append(f"- Android: {android_device}")
    lines.append("")

    lines.append("<details>")
    lines.append("<summary>Detailed interpreted benchmark outputs</summary>")
    lines.append("")
    lines.append("#### iOS")
    lines.append(f"- CSV files parsed: `{ios_count}`")
    lines.extend(ios_lines)
    lines.append("")
    lines.append("#### Android")
    lines.append(f"- CSV files parsed: `{android_count}`")
    lines.extend(android_lines)
    lines.append("")
    lines.append("</details>")
    lines.append("")
    lines.append("### Artifact scan roots")
    lines.append(f"- iOS artifact root: `{ios_dir}`")
    lines.append(f"- Android artifact root: `{android_dir}`")
    lines.append("")
    lines.append("Interpretation mode: descriptive summary only (no regression gate/threshold).")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    markdown = build_markdown(args)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
