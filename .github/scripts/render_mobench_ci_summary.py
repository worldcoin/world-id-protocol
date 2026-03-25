#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
from dataclasses import dataclass
from pathlib import Path


IOS_START_MARKER = "BENCH_REPORT_JSON_START"
IOS_END_MARKER = "BENCH_REPORT_JSON_END"
ANDROID_MARKER = "BENCH_JSON "


@dataclass
class BenchmarkRecord:
    function: str
    label: str
    samples: int
    mean_ns: int
    median_ns: int
    p95_ns: int
    min_ns: int
    max_ns: int


def humanize_function(function: str) -> str:
    leaf = function.rsplit("::", 1)[-1]
    if leaf.startswith("bench_"):
        leaf = leaf[len("bench_") :]
    return leaf.replace("_", "-")


def ns_to_ms(ns: int | None) -> str:
    if ns is None:
        return "—"
    return f"{ns / 1_000_000.0:.2f}"


def percentile(samples: list[int], p: float) -> int:
    if not samples:
        return 0
    rank = math.ceil(len(samples) * p)
    index = max(0, min(len(samples) - 1, rank - 1))
    return samples[index]


def extract_samples(payload: dict) -> list[int]:
    if isinstance(payload.get("samples"), list):
        values: list[int] = []
        for sample in payload["samples"]:
            if isinstance(sample, dict) and isinstance(sample.get("duration_ns"), int):
                values.append(sample["duration_ns"])
            elif isinstance(sample, int):
                values.append(sample)
        if values:
            return values
    if isinstance(payload.get("samples_ns"), list):
        return [value for value in payload["samples_ns"] if isinstance(value, int)]
    return []


def build_record(payload: dict) -> BenchmarkRecord | None:
    function = payload.get("function") or payload.get("spec", {}).get("name")
    if not isinstance(function, str) or not function:
        return None

    samples = sorted(extract_samples(payload))
    if not samples:
        return None

    mean_ns = int(round(sum(samples) / len(samples)))
    median_ns = int(statistics.median(samples))
    return BenchmarkRecord(
        function=function,
        label=humanize_function(function),
        samples=len(samples),
        mean_ns=mean_ns,
        median_ns=median_ns,
        p95_ns=percentile(samples, 0.95),
        min_ns=min(samples),
        max_ns=max(samples),
    )


def extract_ios_reports(text: str) -> list[dict]:
    reports: list[dict] = []
    current: list[str] = []
    capturing = False

    for line in text.splitlines():
        if IOS_START_MARKER in line:
            capturing = True
            current = []
            continue
        if capturing and IOS_END_MARKER in line:
            json_text = "\n".join(current).strip()
            capturing = False
            current = []
            if json_text:
                try:
                    reports.append(json.loads(json_text))
                except json.JSONDecodeError:
                    pass
            continue
        if not capturing:
            continue

        start = line.find("{")
        if start != -1:
            current.append(line[start:].strip())
        elif current:
            current.append(line.strip())

    return reports


def extract_android_reports(text: str) -> list[dict]:
    reports: list[dict] = []
    for line in text.splitlines():
        if ANDROID_MARKER not in line:
            continue
        payload = line.split(ANDROID_MARKER, 1)[1].strip()
        try:
            reports.append(json.loads(payload))
        except json.JSONDecodeError:
            continue
    return reports


def load_expected_functions(artifact_root: Path, platform: str) -> tuple[list[str], dict[str, dict]]:
    expected: list[str] = []
    metadata: dict[str, dict] = {}
    base_dir = artifact_root / "mobench" / "ci" / platform / platform
    for path in sorted(base_dir.glob("*/summary.json")):
        with path.open() as fh:
            data = json.load(fh)
        summary = data.get("summary", {})
        function = summary.get("function")
        if not isinstance(function, str):
            continue
        expected.append(function)
        metadata[function] = {
            "device": ", ".join(summary.get("devices", [])) or "unknown",
            "iterations": summary.get("iterations"),
            "warmup": summary.get("warmup"),
            "target": summary.get("target", platform),
        }
    return expected, metadata


def load_records(artifact_root: Path, platform: str) -> dict[str, BenchmarkRecord]:
    records: dict[str, BenchmarkRecord] = {}

    for path in sorted((artifact_root / "browserstack").glob("*/*/bench-report.json")):
        with path.open() as fh:
            payload = json.load(fh)
        record = build_record(payload)
        if record and record.function not in records:
            records[record.function] = record

    log_names = [
        "testcases_data_0__testcases_0__device_log.log",
        "testcases_data_0__testcases_0__instrumentation_log.log",
    ]
    for log_name in log_names:
        for path in sorted((artifact_root / "browserstack").glob(f"*/*/{log_name}")):
            text = path.read_text(errors="ignore")
            raw_reports = extract_ios_reports(text) if platform == "ios" else extract_android_reports(text)
            for payload in raw_reports:
                record = build_record(payload)
                if record is None:
                    continue
                existing = records.get(record.function)
                if existing is None or record.samples > existing.samples:
                    records[record.function] = record

    return records


def render_markdown(platform_name: str, device: str, iterations: int | None, warmup: int | None, expected: list[str], records: dict[str, BenchmarkRecord]) -> str:
    completed = sum(1 for function in expected if function in records)
    total = len(expected)
    missing = [humanize_function(function) for function in expected if function not in records]

    lines = [
        f"## {platform_name} Benchmark Results",
        "",
        f"- Device: {device}",
        f"- Completed benchmarks: {completed} / {total}",
    ]
    if iterations is not None and warmup is not None:
        lines.append(f"- Iterations/Warmup: {iterations} / {warmup}")
    if missing:
        lines.append(f"- Missing raw reports: {', '.join(missing)}")
    lines.extend(
        [
            "",
            "| Benchmark | Samples | Mean (ms) | Median (ms) | P95 (ms) | Min (ms) | Max (ms) | Status |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )

    for function in expected:
        record = records.get(function)
        label = humanize_function(function)
        if record is None:
            lines.append(f"| {label} | — | — | — | — | — | — | missing |")
            continue
        lines.append(
            "| {label} | {samples} | {mean} | {median} | {p95} | {min_v} | {max_v} | ok |".format(
                label=label,
                samples=record.samples,
                mean=ns_to_ms(record.mean_ns),
                median=ns_to_ms(record.median_ns),
                p95=ns_to_ms(record.p95_ns),
                min_v=ns_to_ms(record.min_ns),
                max_v=ns_to_ms(record.max_ns),
            )
        )

    return "\n".join(lines) + "\n"


def write_csv(path: Path, platform: str, device: str, expected: list[str], records: dict[str, BenchmarkRecord]) -> None:
    with path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "platform",
                "device",
                "function",
                "label",
                "samples",
                "mean_ns",
                "median_ns",
                "p95_ns",
                "min_ns",
                "max_ns",
                "status",
            ]
        )
        for function in expected:
            record = records.get(function)
            writer.writerow(
                [
                    platform,
                    device,
                    function,
                    humanize_function(function),
                    record.samples if record else "",
                    record.mean_ns if record else "",
                    record.median_ns if record else "",
                    record.p95_ns if record else "",
                    record.min_ns if record else "",
                    record.max_ns if record else "",
                    "ok" if record else "missing",
                ]
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--platform", required=True, choices=["ios", "android"])
    parser.add_argument("--markdown-out", required=True)
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--csv-out", required=True)
    args = parser.parse_args()

    artifact_root = Path(args.artifact_root)
    expected, metadata = load_expected_functions(artifact_root, args.platform)
    records = load_records(artifact_root, args.platform)

    if not expected:
        raise SystemExit(f"No expected benchmark summaries found under {artifact_root}")
    if not records:
        raise SystemExit(f"No raw benchmark reports found under {artifact_root}")

    first_meta = metadata[expected[0]]
    platform_name = "iOS" if args.platform == "ios" else "Android"
    device = first_meta["device"]
    iterations = first_meta.get("iterations")
    warmup = first_meta.get("warmup")

    markdown = render_markdown(platform_name, device, iterations, warmup, expected, records)
    markdown_path = Path(args.markdown_out)
    markdown_path.write_text(markdown)

    json_payload = {
        "platform": args.platform,
        "device": device,
        "iterations": iterations,
        "warmup": warmup,
        "completed": sum(1 for function in expected if function in records),
        "total": len(expected),
        "results": [
            {
                "function": function,
                "label": humanize_function(function),
                "status": "ok" if function in records else "missing",
                **(
                    {
                        "samples": records[function].samples,
                        "mean_ns": records[function].mean_ns,
                        "median_ns": records[function].median_ns,
                        "p95_ns": records[function].p95_ns,
                        "min_ns": records[function].min_ns,
                        "max_ns": records[function].max_ns,
                    }
                    if function in records
                    else {}
                ),
            }
            for function in expected
        ],
    }
    Path(args.json_out).write_text(json.dumps(json_payload, indent=2) + "\n")
    write_csv(Path(args.csv_out), args.platform, device, expected, records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
