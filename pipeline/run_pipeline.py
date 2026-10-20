#!/usr/bin/env python3
"""Run opcode flow detection and the flow summary as one organized pipeline."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FILTER_SCRIPT = Path(__file__).resolve().with_name("openvpn_opcode_filter.py")
SUMMARY_SCRIPT = Path(__file__).resolve().with_name("flow_summary.py")
RUNS_DIRECTORY = PROJECT_ROOT / "runs"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run OpenVPN opcode flow detection, save its CSV, and generate a "
            "controlled-aware text summary in one dated run directory."
        )
    )
    parser.add_argument("pcap", type=Path, help="input .pcap file")
    return parser.parse_args()


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed with exit code {result.returncode}: "
            + " ".join(command)
        )
    return result


def main() -> int:
    args = parse_args()
    input_path = args.pcap.expanduser().resolve()
    if not input_path.is_file():
        raise SystemExit(f"input PCAP does not exist: {input_path}")

    filter_result = run_command(
        [sys.executable, str(FILTER_SCRIPT), str(input_path)]
    )
    match = re.search(r"output directory: (.+)\s*$", filter_result.stdout)
    if match is None:
        raise RuntimeError("opcode filter did not report its output directory")

    run_directory = Path(match.group(1)).resolve()
    results_path = run_directory / "openvpn.csv"
    summary_path = run_directory / "flow_summary.txt"
    metadata_path = run_directory / "run_metadata.json"

    summary_result = subprocess.run(
        [sys.executable, str(SUMMARY_SCRIPT), str(results_path)],
        capture_output=True,
        text=True,
    )
    summary_path.write_text(summary_result.stdout, encoding="utf-8")
    if summary_result.stdout:
        print(summary_result.stdout, end="")
    if summary_result.stderr:
        print(summary_result.stderr, end="", file=sys.stderr)
    if summary_result.returncode != 0:
        raise RuntimeError(
            f"flow summary failed with exit code {summary_result.returncode}"
        )

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["pipeline"] = {
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "runner": "pipeline/run_pipeline.py",
        "flow_summary": summary_path.name,
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2) + "\n",
        encoding="utf-8",
    )

    relative_run = run_directory.relative_to(PROJECT_ROOT)
    (RUNS_DIRECTORY / "LATEST_RUN.txt").write_text(
        relative_run.as_posix() + "\n",
        encoding="utf-8",
    )

    print("\nPIPELINE COMPLETE")
    print(f"Run directory:  {run_directory}")
    print(f"Detection CSV:  {results_path}")
    print(f"Summary report: {summary_path}")
    print(f"Run metadata:   {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
