#!/usr/bin/env python3

import csv
import json
import shutil
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

import dpkt


N = 100
ACCEPT_MIN = 4
ACCEPT_MAX = 11
HANDSHAKE_DONE = 4
MAX_OVPN_LEN = 2000
# Zeek's default initial TCP window (tcp_max_initial_window). The reassembler
# buffers at most this much data ABOVE the current in-order point; it bounds the
# OPENING buffer, it is NOT a cap on total bytes.
TCP_MAX_INITIAL_WINDOW = 16 * 1024  # 16384 bytes, Zeek default
VALID_OPCODES = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
RUNS_DIRECTORY = Path(__file__).resolve().parent.parent / "runs"


class StreamReasm:
    """One direction of a TCP connection, reassembled into OpenVPN record opcodes.

    Faithful to Zeek's default-on reassembly, bounded to the opening of the
    connection: anchor at the ISN from the SYN (first data byte = ISN + 1), place
    each segment by its sequence offset, deliver the contiguous in-order run, hold
    anything past a gap, keep first-seen bytes on retransmit/overlap, and walk the
    length-prefixed OpenVPN records ([2-byte length][opcode|keyid byte]) out of the
    in-order bytes. All offsets are kept in unsigned 32-bit sequence space.
    """

    def __init__(self):
        self.anchored = False
        self.base = 0          # sequence number at stream offset 0
        self.next_off = 0      # next in-order offset expected
        self.buf = bytearray() # contiguous unparsed bytes ending at next_off
        self.ooo = {}          # out-of-order segments, keyed by offset
        self.ooo_bytes = 0
        self.stopped = False   # bad framing / excess reorder -> stop this direction

    def note_syn(self, seq):
        """Anchor from the SYN (first data byte = ISN + 1). First SYN seen wins."""
        if not self.anchored:
            self.base = (seq + 1) & 0xFFFFFFFF
            self.anchored = True

    def push(self, seq, payload, out):
        """Feed one TCP segment (seq + payload); append the opcode of every OpenVPN
        record that becomes fully in order to `out`, in order."""
        if self.stopped or not payload:
            return
        if not self.anchored:
            self.base = seq & 0xFFFFFFFF  # best-effort anchor if the SYN was missed
            self.anchored = True

        off = (seq - self.base) & 0xFFFFFFFF
        # Don't buffer data sitting more than one initial window above the current
        # in-order point (too large a hole), nor anything before the anchor (a
        # pre-anchor seq wraps to a huge offset and is caught by the same test).
        if off > self.next_off and (off - self.next_off) > TCP_MAX_INITIAL_WINDOW:
            return

        if off == self.next_off:
            # in order
            self.buf += payload
            self.next_off = (off + len(payload)) & 0xFFFFFFFF
            self._drain()
            self._parse(out)
        elif off < self.next_off:
            # retransmit / overlap: keep first-seen, take only the new tail
            already = self.next_off - off
            if len(payload) > already:
                self.buf += payload[already:]
                self.next_off = (off + len(payload)) & 0xFFFFFFFF
                self._drain()
                self._parse(out)
        else:
            # out of order (gap ahead): buffer it, first copy wins
            if off not in self.ooo:
                self.ooo_bytes += len(payload)
                self.ooo[off] = bytes(payload)
                if self.ooo_bytes > TCP_MAX_INITIAL_WINDOW:
                    self._stop()

    def _stop(self):
        self.stopped = True
        self.buf = bytearray()
        self.ooo = {}
        self.ooo_bytes = 0

    def _drain(self):
        """Pull buffered out-of-order segments that are now contiguous into buf."""
        while self.ooo:
            off = min(self.ooo)
            if off > self.next_off:
                break  # still a gap before the earliest buffered segment
            seg = self.ooo.pop(off)
            self.ooo_bytes -= len(seg)
            end = (off + len(seg)) & 0xFFFFFFFF
            if end > self.next_off:
                already = self.next_off - off
                self.buf += seg[already:]
                self.next_off = end
            # else fully covered already -> dropped

    def _parse(self, out):
        """Walk complete length-prefixed records out of the contiguous buffer."""
        while True:
            if len(self.buf) < 2:
                break  # need the 2-byte length
            length = (self.buf[0] << 8) | self.buf[1]
            if length == 0 or length > MAX_OVPN_LEN:
                self._stop()  # not OpenVPN framing (or started mid-record)
                break
            total = 2 + length
            if len(self.buf) < total:
                break  # record continues in a later segment; wait
            out.append(self.buf[2] >> 3)  # opcode = top 5 bits of the opcode|keyid byte
            del self.buf[0:total]


def decide(window):
    if len(window) < 2:
        return False
    if any(op not in VALID_OPCODES for op in window):
        return False

    cr, sr = window[0], window[1]
    seen = set()
    for op in window:
        if (op == cr or op == sr) and len(seen) >= HANDSHAKE_DONE:
            return False
        seen.add(op)

    return ACCEPT_MIN <= len(seen) <= ACCEPT_MAX


def make_run_directory(input_path, created_at):
    date_directory = RUNS_DIRECTORY / created_at.strftime("%Y-%m-%d")
    date_directory.mkdir(parents=True, exist_ok=True)
    base_name = f"{input_path.stem}__{created_at.strftime('%Y%m%dT%H%M%SZ')}"
    run_directory = date_directory / base_name
    suffix = 1
    while run_directory.exists():
        run_directory = date_directory / f"{base_name}_{suffix:03d}"
        suffix += 1
    run_directory.mkdir()
    return run_directory


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} INPUT.pcap")

    source_path = Path(sys.argv[1]).expanduser().resolve()
    created_at = datetime.now(timezone.utc)
    run_directory = make_run_directory(source_path, created_at)
    input_copy = run_directory / source_path.name
    results_path = run_directory / "results.csv"
    metadata_path = run_directory / "run_metadata.json"
    shutil.copy2(source_path, input_copy)

    flows = {}
    reached = 0
    flagged = []

    with input_copy.open("rb") as capture:
        for _, packet in dpkt.pcap.Reader(capture):
            try:
                ethernet = dpkt.ethernet.Ethernet(packet)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            ip = ethernet.data
            if not isinstance(ip, dpkt.ip.IP):
                continue

            if isinstance(ip.data, dpkt.tcp.TCP):
                proto = "TCP"
                transport = ip.data
                transport_bytes = bytes(transport)
                if len(transport_bytes) < 13:
                    continue
                tcp_header_length = (transport_bytes[12] >> 4) * 4
                payload = transport_bytes[tcp_header_length:]
                tcp_seq = transport.seq
                syn = bool(transport.flags & dpkt.tcp.TH_SYN)
            elif isinstance(ip.data, dpkt.udp.UDP):
                proto = "UDP"
                transport = ip.data
                payload = bytes(transport.data)
            else:
                continue

            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            src = (src_ip, transport.sport)
            dst = (dst_ip, transport.dport)
            key = (proto, min(src, dst), max(src, dst))

            flow = flows.get(key)
            if flow is None:
                flow = {
                    "client": src,
                    "server": dst,
                    "opcodes": [],
                    "decided": False,
                    "dir0": src,  # (ip, port) of the first packet's sender = direction 0
                    # Initial TCP reassembler, one per direction (None for UDP).
                    "reasm": [StreamReasm(), StreamReasm()] if proto == "TCP" else None,
                }
                flows[key] = flow

            if flow["decided"]:
                continue

            # Opcodes of THIS packet.
            #   UDP: one record per datagram -> at most one opcode.
            #   TCP: feed the segment (by sequence) into this direction's reassembler,
            #        which delivers the stream in order and emits an opcode for every
            #        OpenVPN record that becomes complete (0, 1, or several per segment).
            if proto == "UDP":
                new_ops = [payload[0] >> 3] if payload else []
            else:
                direction = 0 if src == flow["dir0"] else 1
                stream = flow["reasm"][direction]
                new_ops = []
                if syn:
                    stream.note_syn(tcp_seq)
                if payload:
                    stream.push(tcp_seq, payload, new_ops)

            if not new_ops:
                continue

            flow["opcodes"].extend(new_ops)
            if len(flow["opcodes"]) < N:
                continue

            flow["decided"] = True
            reached += 1
            # TCP can over-shoot N when a final segment completes several records at
            # once; the window is strictly the first N records.
            window = flow["opcodes"][:N]
            if decide(window):
                client_ip, client_port = flow["client"]
                server_ip, server_port = flow["server"]
                flagged.append(
                    (
                        proto,
                        client_ip,
                        client_port,
                        server_ip,
                        server_port,
                        N,
                        len(set(window)),
                        window[0],
                        window[-1],
                        "|".join(str(op) for op in window),
                    )
                )

    with results_path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(
            (
                "proto",
                "client_ip",
                "client_port",
                "server_ip",
                "server_port",
                "n_eval",
                "unique_opcodes",
                "first_opcode",
                "last_opcode",
                "opcode_sequence",
            )
        )
        writer.writerows(flagged)

    metadata = {
        "run_id": run_directory.name,
        "created_utc": created_at.isoformat(),
        "source_pcap": str(source_path),
        "input_pcap": input_copy.name,
        "input_size_bytes": input_copy.stat().st_size,
        "results_csv": results_path.name,
        "filter_constants": {
            "N": N,
            "ACCEPT_MIN": ACCEPT_MIN,
            "ACCEPT_MAX": ACCEPT_MAX,
            "HANDSHAKE_DONE": HANDSHAKE_DONE,
            "MAX_OVPN_LEN": MAX_OVPN_LEN,
            "TCP_MAX_INITIAL_WINDOW": TCP_MAX_INITIAL_WINDOW,
            "VALID_OPCODES": sorted(VALID_OPCODES),
        },
        "summary": {
            "total_flows_seen": len(flows),
            "flows_reaching_100_opcodes": reached,
            "flows_flagged": len(flagged),
        },
    }
    with metadata_path.open("w", encoding="utf-8") as output:
        json.dump(metadata, output, indent=2)
        output.write("\n")

    print(
        f"total flows seen: {len(flows)}, "
        f"flows that reached 100 opcodes: {reached}, "
        f"flows flagged: {len(flagged)}, "
        f"output directory: {run_directory}"
    )


if __name__ == "__main__":
    main()
