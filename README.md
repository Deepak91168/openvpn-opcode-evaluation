# VPN Traffic Pipeline

This project has one primary workflow: give it a PCAP, detect flows with the
OpenVPN opcode rule, and generate a controlled-aware flow summary.

## Directory layout

```text
openvpn-opcode-evaluation/
├── pipeline/                    Executable Python code and detailed usage
├── data/                        Current source dataset and input PCAP
│   ├── metadata.json
│   └── pcap/
├── runs/                        Pipeline outputs; new runs are grouped by date
│   └── LATEST_RUN.txt           Relative path to the newest completed run
├── .gitattributes               Git LFS rules for source captures
├── .gitignore                   Generated-file exclusions
├── requirements.txt
└── README.md
```

Files under `data/` are inputs. Files under `runs/` are generated results.
Historical experiments intentionally remain outside this project in the
surrounding workspace's `archive/` directory.

The source PCAP is larger than GitHub's normal 100 MB file limit and is marked
for Git LFS. Redundant PCAP copies inside `runs/` stay available locally but
are excluded from Git; their CSV, report, and metadata files can be committed.

## First-time setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Wireshark command-line tools are only required when combining session PCAPs.

## Run the complete pipeline

From the repository root:

```bash
.venv/bin/python pipeline/run_pipeline.py \
  data/pcap/100sessions.pcap
```

Each run creates one self-contained directory such as:

```text
runs/2026-10-20/100sessions__20261020T121457Z/
├── 100sessions.pcap
├── results.csv
├── flow_summary.txt
└── run_metadata.json
```

`runs/LATEST_RUN.txt` points to the newest successfully completed run. The
terminal also prints every generated path.

## Individual tools

```bash
# Detection only
.venv/bin/python pipeline/openvpn_opcode_filter.py INPUT.pcap

# Summarize an existing detector CSV
python3 pipeline/flow_summary.py RESULTS.csv

# Combine session_N/client.pcap captures into a dataset
python3 pipeline/combine_session_pcaps.py SOURCE_SESSIONS OUTPUT_DATASET
```

See [pipeline/README.md](pipeline/README.md) for all flow-summary filters and
endpoint export commands.
