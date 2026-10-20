# Pipeline runs

New runs are grouped by UTC date. Every completed local run contains:

- a preserved copy of the input PCAP (excluded from Git as a redundant copy);
- `openvpn.csv` from OpenVPN opcode flow detection;
- `flow_summary.txt` containing the terminal report;
- `run_metadata.json` containing configuration, provenance, and counts.

`LATEST_RUN.txt` contains the repository-relative path to the newest run that
completed both detection and summary generation.

