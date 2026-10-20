#!/usr/bin/env python3
"""Summarize flow-level CSV output without assuming endpoint direction.

The input CSV is expected to contain one detected flow per row.  General
statistics treat its ``client_*`` and ``server_*`` columns as neutral endpoint
A/B fields.  Directional roles are used only when the caller explicitly
provides ``--client-ip`` and/or ``--destination-ip``.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import math
import statistics
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


REQUIRED_COLUMNS = {
    "proto",
    "client_ip",
    "client_port",
    "server_ip",
    "server_port",
}
SUPPORTED_PROTOCOLS = {"TCP", "UDP"}
TOP_LIMIT = 10
CONTROLLED_SERVER_IP = ipaddress.ip_address("10.208.23.185")


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class Endpoint:
    ip: IPAddress
    port: int

    def sort_key(self) -> tuple[int, int, int]:
        return (self.ip.version, int(self.ip), self.port)


@dataclass(frozen=True)
class Flow:
    protocol: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    packets_collected: int | None
    opened_utc: datetime | None
    pcap_file: str
    close_reason: str
    row_signature: tuple[str, ...]

    def key(self) -> tuple[object, ...]:
        first, second = sorted(
            (self.endpoint_a, self.endpoint_b), key=Endpoint.sort_key
        )
        return (
            self.protocol,
            first.ip.version,
            int(first.ip),
            first.port,
            second.ip.version,
            int(second.ip),
            second.port,
        )


@dataclass
class LoadResult:
    flows: list[Flow]
    csv_rows: int
    exact_duplicate_rows: int
    issues: Counter[str]


def parse_ip(value: str) -> IPAddress:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IP address: {value!r}") from exc


def parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid port: {value!r}") from exc
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port must be between 0 and 65535: {port}")
    return port


def parse_timestamp(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_nonnegative_integer(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def read_flows(path: Path) -> LoadResult:
    issues: Counter[str] = Counter()
    flows: list[Flow] = []
    raw_signatures: Counter[tuple[str, ...]] = Counter()

    try:
        handle = path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise ValueError(f"cannot open input CSV {path}: {exc}") from exc

    try:
        with handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise ValueError(f"input CSV {path} has no header")

            fieldnames = [name.strip() if name is not None else "" for name in reader.fieldnames]
            if len(fieldnames) != len(set(fieldnames)):
                raise ValueError("input CSV contains duplicate column names")
            missing = sorted(REQUIRED_COLUMNS.difference(fieldnames))
            if missing:
                raise ValueError(
                    "input CSV is missing required columns: " + ", ".join(missing)
                )

            # DictReader uses the original header values as keys. The shipped
            # CSV has clean headers; rejecting padded required headers avoids
            # silently looking up the wrong key.
            if fieldnames != reader.fieldnames:
                raise ValueError("input CSV column names must not contain outer whitespace")

            for row in reader:
                extra_values = tuple(row.get(None) or ())
                signature = (
                    tuple((row.get(name) or "") for name in fieldnames) + extra_values
                )
                raw_signatures[signature] += 1

                if None in row:
                    issues["rows_with_extra_columns"] += 1
                    continue

                protocol = (row.get("proto") or "").strip().upper()
                if protocol not in SUPPORTED_PROTOCOLS:
                    issues["unsupported_protocol_rows"] += 1
                    continue

                invalid_ip = False
                try:
                    ip_a = ipaddress.ip_address((row.get("client_ip") or "").strip())
                    ip_b = ipaddress.ip_address((row.get("server_ip") or "").strip())
                except ValueError:
                    invalid_ip = True
                if invalid_ip:
                    issues["invalid_ip_rows"] += 1
                    continue

                try:
                    port_a = parse_port((row.get("client_port") or "").strip())
                    port_b = parse_port((row.get("server_port") or "").strip())
                except argparse.ArgumentTypeError:
                    issues["invalid_port_rows"] += 1
                    continue

                packet_text = row.get("packets_collected")
                packets = (
                    parse_nonnegative_integer(packet_text)
                    if packet_text is not None
                    else None
                )
                if packet_text is None or not packet_text.strip():
                    issues["missing_packet_counts"] += 1
                elif packets is None:
                    issues["invalid_packet_counts"] += 1

                opened_text = row.get("open_utc")
                opened = parse_timestamp(opened_text) if opened_text is not None else None
                if opened_text is None or not opened_text.strip():
                    issues["missing_timestamps"] += 1
                elif opened is None:
                    issues["invalid_timestamps"] += 1

                flows.append(
                    Flow(
                        protocol=protocol,
                        endpoint_a=Endpoint(ip_a, port_a),
                        endpoint_b=Endpoint(ip_b, port_b),
                        packets_collected=packets,
                        opened_utc=opened,
                        pcap_file=(row.get("pcap_file") or "").strip(),
                        close_reason=(row.get("close_reason") or "").strip(),
                        row_signature=signature,
                    )
                )
    except csv.Error as exc:
        raise ValueError(f"cannot parse input CSV {path}: {exc}") from exc

    exact_duplicates = sum(count - 1 for count in raw_signatures.values())
    return LoadResult(
        flows=flows,
        csv_rows=sum(raw_signatures.values()),
        exact_duplicate_rows=exact_duplicates,
        issues=issues,
    )


def count_extras(values: Iterable[object]) -> tuple[int, int]:
    counts = Counter(values)
    return len(counts), sum(count - 1 for count in counts.values())


def exact_duplicate_count(flows: Sequence[Flow]) -> int:
    return sum(
        count - 1 for count in Counter(flow.row_signature for flow in flows).values()
    )


def unique_ips(flows: Sequence[Flow]) -> set[IPAddress]:
    return {
        endpoint.ip
        for flow in flows
        for endpoint in (flow.endpoint_a, flow.endpoint_b)
    }


def ip_pair_key(flow: Flow) -> tuple[tuple[int, int], tuple[int, int]]:
    addresses = sorted(
        (
            (flow.endpoint_a.ip.version, int(flow.endpoint_a.ip)),
            (flow.endpoint_b.ip.version, int(flow.endpoint_b.ip)),
        )
    )
    return addresses[0], addresses[1]


def related_endpoints(flow: Flow, selected_ip: IPAddress) -> list[Endpoint]:
    a_matches = flow.endpoint_a.ip == selected_ip
    b_matches = flow.endpoint_b.ip == selected_ip
    if a_matches and b_matches:
        return [flow.endpoint_a, flow.endpoint_b]
    if a_matches:
        return [flow.endpoint_b]
    if b_matches:
        return [flow.endpoint_a]
    return []


def endpoints_with_ip(flow: Flow, selected_ip: IPAddress) -> list[Endpoint]:
    return [
        endpoint
        for endpoint in (flow.endpoint_a, flow.endpoint_b)
        if endpoint.ip == selected_ip
    ]


def select_flows(
    flows: Sequence[Flow],
    *,
    neutral_ip: IPAddress | None,
    client_ip: IPAddress | None,
    destination_ip: IPAddress | None,
    destination_port: int | None,
) -> list[Flow]:
    selected: list[Flow] = []
    for flow in flows:
        if neutral_ip is not None:
            if related_endpoints(flow, neutral_ip):
                selected.append(flow)
            continue

        if client_ip is not None and not endpoints_with_ip(flow, client_ip):
            continue
        if destination_ip is not None and not endpoints_with_ip(flow, destination_ip):
            continue

        if destination_port is not None:
            if destination_ip is not None:
                destination_endpoints = endpoints_with_ip(flow, destination_ip)
            elif client_ip is not None:
                destination_endpoints = related_endpoints(flow, client_ip)
            else:
                destination_endpoints = []
            if not any(endpoint.port == destination_port for endpoint in destination_endpoints):
                continue

        selected.append(flow)
    return selected


def format_integer(value: int) -> str:
    return f"{value:,}"


def format_number(value: float | int) -> str:
    if isinstance(value, float) and not value.is_integer():
        return f"{value:,.1f}"
    return format_integer(int(value))


def format_percentage(part: int, whole: int) -> str:
    return "N/A" if whole == 0 else f"{100.0 * part / whole:.1f}%"


def format_datetime(value: datetime | None) -> str:
    return "N/A" if value is None else value.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "N/A"
    milliseconds = int(round(seconds * 1000))
    days, milliseconds = divmod(milliseconds, 86_400_000)
    hours, milliseconds = divmod(milliseconds, 3_600_000)
    minutes, milliseconds = divmod(milliseconds, 60_000)
    whole_seconds, milliseconds = divmod(milliseconds, 1000)
    pieces: list[str] = []
    if days:
        pieces.append(f"{days}d")
    if hours or days:
        pieces.append(f"{hours}h")
    if minutes or hours or days:
        pieces.append(f"{minutes}m")
    if milliseconds:
        pieces.append(f"{whole_seconds}.{milliseconds:03d}s")
    else:
        pieces.append(f"{whole_seconds}s")
    return " ".join(pieces)


def print_section(title: str) -> None:
    print(f"\n{title}")
    print("-" * len(title))


def print_metrics(metrics: Iterable[tuple[str, object]]) -> None:
    for label, value in metrics:
        print(f"{label:<29}: {value}")


def packet_total(flows: Sequence[Flow]) -> str:
    available = [
        flow.packets_collected
        for flow in flows
        if flow.packets_collected is not None
    ]
    if not available:
        return "N/A"
    total = format_integer(sum(available))
    missing = len(flows) - len(available)
    return total if missing == 0 else f"{total} ({missing} rows unavailable)"


def timing_metrics(flows: Sequence[Flow]) -> tuple[datetime | None, datetime | None, float | None]:
    times = sorted(flow.opened_utc for flow in flows if flow.opened_utc is not None)
    if not times:
        return None, None, None
    return times[0], times[-1], (times[-1] - times[0]).total_seconds()


def protocol_counts(flows: Sequence[Flow]) -> Counter[str]:
    return Counter(flow.protocol for flow in flows)


def controlled_client_endpoint(flow: Flow) -> Endpoint | None:
    a_is_server = flow.endpoint_a.ip == CONTROLLED_SERVER_IP
    b_is_server = flow.endpoint_b.ip == CONTROLLED_SERVER_IP
    if a_is_server and not b_is_server:
        return flow.endpoint_b
    if b_is_server and not a_is_server:
        return flow.endpoint_a
    if a_is_server and b_is_server:
        return flow.endpoint_a
    return None


def print_controlled_summary(flows: Sequence[Flow]) -> None:
    controlled = [
        flow for flow in flows if controlled_client_endpoint(flow) is not None
    ]
    protocols = protocol_counts(controlled)
    client_flow_counts: Counter[IPAddress] = Counter()
    client_protocol_counts: dict[IPAddress, Counter[str]] = {}
    client_ports: dict[IPAddress, set[int]] = {}
    server_ports: set[int] = set()

    for flow in controlled:
        client = controlled_client_endpoint(flow)
        if client is None:
            continue
        client_flow_counts[client.ip] += 1
        client_protocol_counts.setdefault(client.ip, Counter())[flow.protocol] += 1
        client_ports.setdefault(client.ip, set()).add(client.port)
        for endpoint in (flow.endpoint_a, flow.endpoint_b):
            if endpoint.ip == CONTROLLED_SERVER_IP:
                server_ports.add(endpoint.port)

    print_section("CONTROLLED TRAFFIC")
    print_metrics(
        [
            ("Controlled server IP", str(CONTROLLED_SERVER_IP)),
            (
                "Controlled flow records",
                f"{format_integer(len(controlled))} "
                f"({format_percentage(len(controlled), len(flows))})",
            ),
            ("Other flow records", format_integer(len(flows) - len(controlled))),
            ("Controlled TCP flows", format_integer(protocols["TCP"])),
            ("Controlled UDP flows", format_integer(protocols["UDP"])),
            ("Associated client IPs", format_integer(len(client_flow_counts))),
            ("Controlled server ports", format_integer(len(server_ports))),
        ]
    )

    print_section("CONTROLLED CLIENT IPS")
    rows = []
    for address, count in sorted(
        client_flow_counts.items(),
        key=lambda item: (-item[1], item[0].version, int(item[0])),
    ):
        counts = client_protocol_counts[address]
        rows.append(
            (
                str(address),
                format_integer(count),
                format_percentage(count, len(controlled)),
                format_integer(counts["TCP"]),
                format_integer(counts["UDP"]),
                format_integer(len(client_ports[address])),
            )
        )
    print_table(
        ("CLIENT IP", "FLOWS", "SHARE", "TCP", "UDP", "CLIENT PORTS"),
        rows,
    )


def print_flow_summary(
    title: str,
    flows: Sequence[Flow],
    *,
    total_for_share: int | None = None,
    include_network: bool = True,
) -> None:
    unique_flow_count, repeated_records = count_extras(flow.key() for flow in flows)
    protocols = protocol_counts(flows)
    first, last, span = timing_metrics(flows)
    pcap_count = len({flow.pcap_file for flow in flows if flow.pcap_file})
    flow_count_text = format_integer(len(flows))
    if total_for_share is not None:
        flow_count_text += f" ({format_percentage(len(flows), total_for_share)})"

    metrics: list[tuple[str, object]] = [
        ("Total flow records", flow_count_text),
        ("Unique flow keys", format_integer(unique_flow_count)),
        ("Repeated flow records", format_integer(repeated_records)),
        ("Exact duplicate rows", format_integer(exact_duplicate_count(flows))),
        (
            "TCP flows",
            f"{format_integer(protocols['TCP'])} "
            f"({format_percentage(protocols['TCP'], len(flows))})",
        ),
        (
            "UDP flows",
            f"{format_integer(protocols['UDP'])} "
            f"({format_percentage(protocols['UDP'], len(flows))})",
        ),
        ("Packets collected", packet_total(flows)),
    ]
    if include_network:
        metrics.extend(
            [
                ("Unique IP addresses", format_integer(len(unique_ips(flows)))),
                (
                    "Unique IP pairs (IP only)",
                    format_integer(len({ip_pair_key(flow) for flow in flows})),
                ),
            ]
        )
    metrics.extend(
        [
            ("Source PCAP files", format_integer(pcap_count)),
            ("First flow opened", format_datetime(first)),
            ("Last flow opened", format_datetime(last)),
            ("Flow-opening time span", format_duration(span)),
        ]
    )
    print_section(title)
    print_metrics(metrics)


def endpoint_sort_key(endpoint: Endpoint) -> tuple[int, int, int]:
    return endpoint.sort_key()


def format_ip_pair(pair: tuple[tuple[int, int], tuple[int, int]]) -> str:
    first = (
        ipaddress.IPv4Address(pair[0][1])
        if pair[0][0] == 4
        else ipaddress.IPv6Address(pair[0][1])
    )
    second = (
        ipaddress.IPv4Address(pair[1][1])
        if pair[1][0] == 4
        else ipaddress.IPv6Address(pair[1][1])
    )
    return f"{first} <-> {second}"


def print_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> None:
    text_rows = [[str(value) for value in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in text_rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in text_rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def print_details(flows: Sequence[Flow], title_suffix: str) -> None:
    pair_counts = Counter(ip_pair_key(flow) for flow in flows)
    print_section(f"TOP IP PAIRS{title_suffix}")
    print_table(
        ("IP PAIR", "FLOWS", "SHARE"),
        [
            (format_ip_pair(pair), format_integer(count), format_percentage(count, len(flows)))
            for pair, count in pair_counts.most_common(TOP_LIMIT)
        ],
    )

    participation: Counter[IPAddress] = Counter()
    for flow in flows:
        # One flow counts once per participating IP, including self-IP flows.
        participation.update({flow.endpoint_a.ip, flow.endpoint_b.ip})
    top_ips = sorted(
        participation.items(),
        key=lambda item: (-item[1], item[0].version, int(item[0])),
    )[:TOP_LIMIT]
    print_section(f"TOP PARTICIPATING IPS{title_suffix}")
    print_table(
        ("IP", "FLOWS", "SHARE"),
        [
            (str(address), format_integer(count), format_percentage(count, len(flows)))
            for address, count in top_ips
        ],
    )

    pcap_counts = Counter(flow.pcap_file for flow in flows if flow.pcap_file)
    print_section(f"CAPTURE COVERAGE{title_suffix}")
    print_table(
        ("PCAP FILE", "FLOWS"),
        [
            (name, format_integer(count))
            for name, count in sorted(pcap_counts.items())
        ],
    )

    packet_counts = sorted(
        flow.packets_collected
        for flow in flows
        if flow.packets_collected is not None
    )
    print_section(f"PACKET COUNTS{title_suffix}")
    if packet_counts:
        p95_index = max(0, math.ceil(0.95 * len(packet_counts)) - 1)
        print_metrics(
            [
                ("Rows with packet counts", format_integer(len(packet_counts))),
                ("Minimum", format_integer(packet_counts[0])),
                ("Median", format_number(statistics.median(packet_counts))),
                ("95th percentile", format_integer(packet_counts[p95_index])),
                ("Maximum", format_integer(packet_counts[-1])),
            ]
        )
    else:
        print_metrics([("Rows with packet counts", "0")])

    reason_counts = Counter(flow.close_reason or "(missing)" for flow in flows)
    print_section(f"CLOSE REASONS{title_suffix}")
    print_table(
        ("CLOSE REASON", "FLOWS", "SHARE"),
        [
            (reason, format_integer(count), format_percentage(count, len(flows)))
            for reason, count in reason_counts.most_common()
        ],
    )

    times = sorted(flow.opened_utc for flow in flows if flow.opened_utc is not None)
    print_section(f"TIMING GAPS{title_suffix}")
    if len(times) < 2:
        print_metrics([("Largest opening gap", "N/A")])
    else:
        gap_start, gap_end = max(zip(times, times[1:]), key=lambda pair: pair[1] - pair[0])
        print_metrics(
            [
                ("Largest opening gap", format_duration((gap_end - gap_start).total_seconds())),
                ("Gap started", format_datetime(gap_start)),
                ("Next flow opened", format_datetime(gap_end)),
            ]
        )


def print_data_quality(load_result: LoadResult) -> None:
    print_section("DATA QUALITY")
    skipped = load_result.csv_rows - len(load_result.flows)
    repeated_key_count = sum(
        count > 1 for count in Counter(flow.key() for flow in load_result.flows).values()
    )
    metrics: list[tuple[str, object]] = [
        ("Skipped rows", format_integer(skipped)),
        ("Repeated flow keys", format_integer(repeated_key_count)),
        ("Exact duplicate CSV rows", format_integer(load_result.exact_duplicate_rows)),
    ]
    labels = {
        "unsupported_protocol_rows": "Unsupported protocol rows",
        "invalid_ip_rows": "Invalid-IP rows",
        "invalid_port_rows": "Invalid-port rows",
        "rows_with_extra_columns": "Rows with extra columns",
        "missing_packet_counts": "Missing packet counts",
        "invalid_packet_counts": "Invalid packet counts",
        "missing_timestamps": "Missing timestamps",
        "invalid_timestamps": "Invalid timestamps",
    }
    metrics.extend(
        (label, format_integer(load_result.issues[key]))
        for key, label in labels.items()
        if load_result.issues[key]
    )
    print_metrics(metrics)


def print_endpoint_list(title: str, endpoints: set[Endpoint]) -> None:
    rows = [
        (str(endpoint.ip), endpoint.port)
        for endpoint in sorted(endpoints, key=endpoint_sort_key)
    ]
    print_section(title)
    print_table(("IP", "PORT"), rows)


def write_endpoint_csv(
    path: Path,
    endpoints: set[Endpoint],
    *,
    force: bool,
    input_path: Path,
) -> None:
    try:
        if path.resolve() == input_path.resolve():
            raise ValueError("endpoint output path cannot be the input CSV")
    except OSError:
        # Resolution can fail for a not-yet-created parent; the direct path
        # equality check still catches the common case.
        if path.absolute() == input_path.absolute():
            raise ValueError("endpoint output path cannot be the input CSV")

    if path.exists() and not force:
        raise ValueError(f"output file already exists: {path} (use --force to replace it)")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(("ip", "port"))
            for endpoint in sorted(endpoints, key=endpoint_sort_key):
                writer.writerow((str(endpoint.ip), endpoint.port))
    except OSError as exc:
        raise ValueError(f"cannot write endpoint CSV {path}: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize a flow CSV. Endpoint roles are neutral unless client or "
            "destination roles are explicitly supplied."
        ),
        epilog="Full documentation: pipeline/README.md",
    )
    parser.add_argument("csv_file", type=Path, help="flow-level CSV to analyze")
    parser.add_argument("--ip", type=parse_ip, help="analyze an IP without assigning a role")
    parser.add_argument("--client-ip", type=parse_ip, help="user-declared client IP")
    parser.add_argument("--destination-ip", type=parse_ip, help="user-declared destination IP")
    parser.add_argument(
        "--destination-port",
        type=parse_port,
        help="optionally restrict the user-declared destination port",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="show raw top-pair, IP, capture, packet, close-reason, and timing tables",
    )
    outputs = parser.add_mutually_exclusive_group()
    outputs.add_argument(
        "--destinations-csv",
        type=Path,
        help="print and save unique destination IP/port pairs (requires --client-ip)",
    )
    outputs.add_argument(
        "--peers-csv",
        type=Path,
        help="print and save unique peer IP/port pairs (requires --ip)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing endpoint CSV",
    )
    return parser


def validate_arguments(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.ip is not None and (args.client_ip is not None or args.destination_ip is not None):
        parser.error("--ip cannot be combined with --client-ip or --destination-ip")
    if (
        args.destination_port is not None
        and args.client_ip is None
        and args.destination_ip is None
    ):
        parser.error("--destination-port requires --client-ip or --destination-ip")
    if args.client_ip is not None and args.destination_ip is not None:
        if args.client_ip == args.destination_ip:
            parser.error("--client-ip and --destination-ip must be different")
    if args.destinations_csv is not None and args.client_ip is None:
        parser.error("--destinations-csv requires --client-ip")
    if args.peers_csv is not None and args.ip is None:
        parser.error("--peers-csv requires --ip")
    if args.force and args.destinations_csv is None and args.peers_csv is None:
        parser.error("--force requires --destinations-csv or --peers-csv")
    if not args.csv_file.is_file():
        parser.error(f"input CSV does not exist or is not a file: {args.csv_file}")

    output_path = args.destinations_csv or args.peers_csv
    if output_path is not None:
        try:
            same_as_input = output_path.resolve() == args.csv_file.resolve()
        except OSError:
            same_as_input = output_path.absolute() == args.csv_file.absolute()
        if same_as_input:
            parser.error("endpoint output path cannot be the input CSV")
        if output_path.exists() and not args.force:
            parser.error(
                f"output file already exists: {output_path} (use --force to replace it)"
            )


def selected_mode(args: argparse.Namespace) -> bool:
    return any(
        value is not None for value in (args.ip, args.client_ip, args.destination_ip)
    )


def selection_title(args: argparse.Namespace) -> str:
    if args.ip is not None:
        return "IP-SPECIFIC ANALYSIS"
    if args.client_ip is not None and args.destination_ip is not None:
        return "CLIENT TO DESTINATION ANALYSIS"
    if args.client_ip is not None:
        return "CLIENT-IP ANALYSIS"
    return "DESTINATION-IP ANALYSIS"


def selection_identity_metrics(args: argparse.Namespace) -> list[tuple[str, object]]:
    metrics: list[tuple[str, object]] = []
    if args.ip is not None:
        metrics.append(("Selected IP", str(args.ip)))
    if args.client_ip is not None:
        metrics.append(("Client IP", str(args.client_ip)))
    if args.destination_ip is not None:
        metrics.append(("Destination IP", str(args.destination_ip)))
    if args.destination_port is not None:
        metrics.append(("Destination port", args.destination_port))
    return metrics


def role_endpoints(args: argparse.Namespace, flows: Sequence[Flow]) -> tuple[str, set[Endpoint]]:
    if args.ip is not None:
        endpoints = {
            endpoint
            for flow in flows
            for endpoint in related_endpoints(flow, args.ip)
        }
        return "Peer", endpoints
    if args.client_ip is not None and args.destination_ip is None:
        endpoints = {
            endpoint
            for flow in flows
            for endpoint in related_endpoints(flow, args.client_ip)
        }
        return "Destination", endpoints
    if args.destination_ip is not None and args.client_ip is None:
        endpoints = {
            endpoint
            for flow in flows
            for endpoint in related_endpoints(flow, args.destination_ip)
        }
        return "Client", endpoints
    if args.destination_ip is not None:
        endpoints = {
            endpoint
            for flow in flows
            for endpoint in endpoints_with_ip(flow, args.destination_ip)
        }
        return "Destination", endpoints
    return "Related", set()


def run(args: argparse.Namespace) -> int:
    try:
        loaded = read_flows(args.csv_file)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print_section("INPUT")
    print_metrics(
        [
            ("CSV file", args.csv_file),
            ("CSV rows", format_integer(loaded.csv_rows)),
            ("Valid TCP/UDP rows", format_integer(len(loaded.flows))),
        ]
    )
    print_flow_summary("OVERALL TRAFFIC", loaded.flows)
    print_controlled_summary(loaded.flows)

    detail_flows: Sequence[Flow] = loaded.flows
    detail_suffix = ""
    selected: list[Flow] = []
    endpoints: set[Endpoint] = set()
    endpoint_role = "Related"

    if selected_mode(args):
        selected = select_flows(
            loaded.flows,
            neutral_ip=args.ip,
            client_ip=args.client_ip,
            destination_ip=args.destination_ip,
            destination_port=args.destination_port,
        )
        selected_keys = {id(flow) for flow in selected}
        outside = [flow for flow in loaded.flows if id(flow) not in selected_keys]

        print_section(selection_title(args))
        print_metrics(selection_identity_metrics(args))
        # Keep identity and statistics in the same section without repeating a
        # second heading.
        unique_count, repeated = count_extras(flow.key() for flow in selected)
        counts = protocol_counts(selected)
        first, last, span = timing_metrics(selected)
        print_metrics(
            [
                (
                    "Matched flow records",
                    f"{format_integer(len(selected))} "
                    f"({format_percentage(len(selected), len(loaded.flows))})",
                ),
                ("Unique flow keys", format_integer(unique_count)),
                ("Repeated flow records", format_integer(repeated)),
                ("Exact duplicate rows", format_integer(exact_duplicate_count(selected))),
                (
                    "TCP flows",
                    f"{format_integer(counts['TCP'])} "
                    f"({format_percentage(counts['TCP'], len(selected))})",
                ),
                (
                    "UDP flows",
                    f"{format_integer(counts['UDP'])} "
                    f"({format_percentage(counts['UDP'], len(selected))})",
                ),
                ("Packets collected", packet_total(selected)),
                (
                    "Source PCAP files",
                    format_integer(
                        len({flow.pcap_file for flow in selected if flow.pcap_file})
                    ),
                ),
                ("First flow opened", format_datetime(first)),
                ("Last flow opened", format_datetime(last)),
                ("Flow-opening time span", format_duration(span)),
            ]
        )

        endpoint_role, endpoints = role_endpoints(args, selected)
        print_metrics(
            [
                (
                    f"Unique {endpoint_role.lower()} IPs",
                    format_integer(len({endpoint.ip for endpoint in endpoints})),
                ),
                (f"Unique {endpoint_role.lower()} IP:ports", format_integer(len(endpoints))),
            ]
        )

        print_flow_summary(
            "TRAFFIC OUTSIDE FILTER",
            outside,
            total_for_share=len(loaded.flows),
            include_network=True,
        )
        detail_flows = selected
        detail_suffix = " (MATCHED TRAFFIC)"

    if args.details:
        print_details(detail_flows, detail_suffix)
        print_data_quality(loaded)
    elif loaded.issues or loaded.exact_duplicate_rows:
        print_data_quality(loaded)

    output_path: Path | None = None
    endpoint_title: str | None = None
    if args.destinations_csv is not None:
        output_path = args.destinations_csv
        endpoint_title = "DESTINATION ENDPOINTS"
    elif args.peers_csv is not None:
        output_path = args.peers_csv
        endpoint_title = "PEER ENDPOINTS"

    if output_path is not None and endpoint_title is not None:
        print_endpoint_list(endpoint_title, endpoints)
        try:
            write_endpoint_csv(
                output_path,
                endpoints,
                force=args.force,
                input_path=args.csv_file,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print_metrics([("Endpoint CSV", output_path)])

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_arguments(parser, args)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
