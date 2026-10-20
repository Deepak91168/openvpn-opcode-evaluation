#!/usr/bin/env python3
"""Combine numerically ordered session PCAPs and write a JSON manifest.

The input directory is expected to contain directories named ``session_N``
(zero padding is optional), each containing a capture such as ``client.pcap``.
Captures are appended in numeric session order; packet timestamps are not used
to reorder packets between sessions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SESSION_DIRECTORY_RE = re.compile(r"^session_(\d+)$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Append session PCAPs in numeric order and create metadata.json."
    )
    parser.add_argument(
        "source_directory",
        type=Path,
        help="Directory containing session_0001, session_0002, ...",
    )
    parser.add_argument(
        "output_directory",
        type=Path,
        help="Output dataset directory (the PCAP is placed in its pcap/ subdirectory)",
    )
    parser.add_argument(
        "--input-name",
        default="client.pcap",
        help="Capture filename inside each session directory (default: client.pcap)",
    )
    parser.add_argument(
        "--output-name",
        default="combined_sessions.pcap",
        help="Combined capture filename (default: combined_sessions.pcap)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing combined PCAP and metadata files",
    )
    return parser.parse_args()


def discover_sessions(source_directory: Path, input_name: str) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    seen_ids: dict[int, str] = {}

    for entry in source_directory.iterdir():
        match = SESSION_DIRECTORY_RE.fullmatch(entry.name)
        if not entry.is_dir() or match is None:
            continue

        session_id = int(match.group(1))
        if session_id in seen_ids:
            raise ValueError(
                f"Duplicate numeric session ID {session_id}: "
                f"{seen_ids[session_id]!r} and {entry.name!r}"
            )
        seen_ids[session_id] = entry.name

        pcap_path = entry / input_name
        if not pcap_path.is_file():
            raise FileNotFoundError(f"Missing capture for {entry.name}: {pcap_path}")

        session_metadata = read_optional_json(entry / "metadata.json")
        sessions.append(
            {
                "session_id": session_id,
                "session_name": entry.name,
                "directory": entry.resolve(),
                "pcap_path": pcap_path.resolve(),
                "pcap_size_bytes": pcap_path.stat().st_size,
                "status": session_metadata.get("status"),
                "start_time": session_metadata.get("start_time"),
                "end_time": session_metadata.get("end_time"),
                "declared_packet_count": session_metadata.get("stats", {}).get(
                    "packet_count"
                ),
            }
        )

    sessions.sort(key=lambda item: item["session_id"])
    if not sessions:
        raise ValueError(f"No session_N directories found in {source_directory}")
    return sessions


def read_optional_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Cannot read valid JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def command_version(executable: str) -> str:
    result = subprocess.run(
        [executable, "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.splitlines()[0].strip()


def packet_count(pcap_path: Path) -> int:
    capinfos = shutil.which("capinfos")
    if capinfos is None:
        raise RuntimeError("capinfos is required to validate the combined capture")
    result = subprocess.run(
        [capinfos, "-c", "-M", str(pcap_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    match = re.search(r"^Number of packets:\s+([\d,]+)\s*$", result.stdout, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"Could not parse packet count from capinfos output: {result.stdout}")
    return int(match.group(1).replace(",", ""))


def sha256sum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as capture_file:
        for chunk in iter(lambda: capture_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def combine(
    source_directory: Path,
    output_directory: Path,
    input_name: str,
    output_name: str,
    overwrite: bool,
) -> tuple[Path, Path]:
    source_directory = source_directory.expanduser().resolve()
    output_directory = output_directory.expanduser().resolve()
    if not source_directory.is_dir():
        raise NotADirectoryError(f"Source directory does not exist: {source_directory}")
    if Path(output_name).name != output_name:
        raise ValueError("--output-name must be a filename, not a path")

    mergecap = shutil.which("mergecap")
    if mergecap is None:
        raise RuntimeError("mergecap is required; install Wireshark CLI utilities")

    sessions = discover_sessions(source_directory, input_name)
    pcap_directory = output_directory / "pcap"
    combined_path = pcap_directory / output_name
    metadata_path = output_directory / "metadata.json"
    existing = [path for path in (combined_path, metadata_path) if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Output already exists; use --overwrite to replace it: "
            + ", ".join(str(path) for path in existing)
        )

    pcap_directory.mkdir(parents=True, exist_ok=True)
    output_directory.mkdir(parents=True, exist_ok=True)

    # A temporary file prevents a failed merge from leaving a partial final PCAP.
    with tempfile.NamedTemporaryFile(
        prefix=f".{combined_path.stem}.", suffix=".tmp.pcap", dir=pcap_directory, delete=False
    ) as temp_file:
        temporary_path = Path(temp_file.name)

    try:
        command = [
            mergecap,
            "-a",  # Append in the given order instead of merging by timestamp.
            "-F",
            "pcap",
            "-w",
            str(temporary_path),
            *(str(session["pcap_path"]) for session in sessions),
        ]
        subprocess.run(command, check=True)

        combined_packet_count = packet_count(temporary_path)
        expected_packet_count = sum(
            int(session["declared_packet_count"])
            for session in sessions
            if session["declared_packet_count"] is not None
        )
        all_counts_available = all(
            session["declared_packet_count"] is not None for session in sessions
        )
        if all_counts_available and combined_packet_count != expected_packet_count:
            raise RuntimeError(
                "Combined packet count does not match the sum recorded in session metadata: "
                f"{combined_packet_count} != {expected_packet_count}"
            )

        combined_sha256 = sha256sum(temporary_path)
        combined_size = temporary_path.stat().st_size
        temporary_path.replace(combined_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise

    successful_count = sum(session["status"] == "successful" for session in sessions)
    manifest_sessions = [
        {
            "merge_position": index,
            "session_id": session["session_id"],
            "session_name": session["session_name"],
            "source_pcap": str(session["pcap_path"]),
            "source_pcap_size_bytes": session["pcap_size_bytes"],
            "declared_packet_count": session["declared_packet_count"],
            "status": session["status"],
            "start_time": session["start_time"],
            "end_time": session["end_time"],
        }
        for index, session in enumerate(sessions, start=1)
    ]
    manifest = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_directory": str(source_directory),
        "output_directory": str(output_directory),
        "ordering": "numeric session ID ascending; captures appended without timestamp sorting",
        "session_count": len(sessions),
        "successful_session_count": successful_count,
        "non_successful_or_unknown_session_count": len(sessions) - successful_count,
        "first_session": sessions[0]["session_name"],
        "last_session": sessions[-1]["session_name"],
        "input_pcap_name": input_name,
        "input_total_size_bytes": sum(session["pcap_size_bytes"] for session in sessions),
        "combined_pcap": {
            "relative_path": combined_path.relative_to(output_directory).as_posix(),
            "format": "pcap",
            "size_bytes": combined_size,
            "packet_count": combined_packet_count,
            "sha256": combined_sha256,
        },
        "merge_tool": command_version(mergecap),
        "sessions": manifest_sessions,
    }

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix=".metadata.",
        suffix=".tmp.json",
        dir=output_directory,
        delete=False,
    ) as temp_metadata:
        json.dump(manifest, temp_metadata, indent=2)
        temp_metadata.write("\n")
        temp_metadata_path = Path(temp_metadata.name)
    temp_metadata_path.replace(metadata_path)

    return combined_path, metadata_path


def main() -> None:
    args = parse_args()
    combined_path, metadata_path = combine(
        source_directory=args.source_directory,
        output_directory=args.output_directory,
        input_name=args.input_name,
        output_name=args.output_name,
        overwrite=args.overwrite,
    )
    print(f"Combined PCAP: {combined_path}")
    print(f"Metadata:      {metadata_path}")


if __name__ == "__main__":
    main()
