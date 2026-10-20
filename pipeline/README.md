# Pipeline command reference

This directory contains the complete workflow for processing a PCAP:

```text
input .pcap
    -> OpenVPN opcode flow detection
    -> openvpn.csv
    -> human-readable flow_summary.txt
```

| Goal | Command |
| --- | --- |
| Detect flows and generate the summary | `pipeline/run_pipeline.py INPUT.pcap` |
| Run only opcode detection | `pipeline/openvpn_opcode_filter.py INPUT.pcap` |
| Summarize an existing detector CSV | `pipeline/flow_summary.py OPENVPN.csv` |
| Combine numbered session captures | `pipeline/combine_session_pcaps.py SOURCE OUTPUT` |

Run all commands below from the repository root:

```bash
cd /home/deepaksingh/Documents/vpn-traffic/openvpn-opcode-evaluation
```

## First-time setup

Python 3 and `dpkt` are required. Create a project-local virtual environment
and install the pinned dependency:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

The examples use `.venv/bin/python`. You can use `python3` instead when `dpkt`
is already installed for that interpreter.

## Recommended: run the complete pipeline

`run_pipeline.py` is the normal entry point. It accepts one PCAP path, runs the
opcode detector, runs the flow summary on the resulting CSV, and records all
outputs together in a timestamped directory.

Usage:

```text
python pipeline/run_pipeline.py INPUT.pcap
```

Example using the PCAP included with this repository:

```bash
.venv/bin/python pipeline/run_pipeline.py \
  data/pcap/session_100.pcap
```

Example using any external capture:

```bash
.venv/bin/python pipeline/run_pipeline.py \
  /absolute/path/to/capture.pcap
```

The command prints the detector counts, summary, and final output paths. A run
for `capture.pcap` creates a directory similar to:

```text
runs/2026-10-20/capture__20261020T122411Z/
├── capture.pcap          Copy of the exact input capture used for this run
├── openvpn.csv           Flows accepted by the opcode detector
├── flow_summary.txt      Saved human-readable analysis of openvpn.csv
└── run_metadata.json     Input path, constants, counts, and run timestamps
```

`runs/LATEST_RUN.txt` is updated only after the complete pipeline succeeds. It
contains the repository-relative path of the newest completed run.

To inspect the newest run:

```bash
cat runs/LATEST_RUN.txt
```

## Run only the OpenVPN opcode detector

`openvpn_opcode_filter.py` accepts exactly one input PCAP. It processes packets
in capture order, groups both directions of a TCP/UDP conversation into one
flow, extracts OpenVPN opcodes, and evaluates a flow once it obtains its first
100 opcodes.

Usage:

```text
python pipeline/openvpn_opcode_filter.py INPUT.pcap
```

Example:

```bash
.venv/bin/python pipeline/openvpn_opcode_filter.py \
  data/pcap/session_100.pcap
```

An absolute input path works as well:

```bash
.venv/bin/python pipeline/openvpn_opcode_filter.py \
  /home/deepaksingh/Documents/vpn-traffic/data/pcap/combined_client_traffic_cleaned.pcap
```

The detector automatically creates a unique directory under
`runs/YYYY-MM-DD/`, using the current UTC date and timestamp. It copies the
input PCAP into that directory and writes:

- `openvpn.csv` — one row per flow accepted by the opcode rule.
- `run_metadata.json` — source/input details, filter constants, and counts.
- `<input-name>.pcap` — the copied input used for reproducibility.

The detector-only command does **not** create `flow_summary.txt` and does not
update `runs/LATEST_RUN.txt`; use `run_pipeline.py` when you want those steps.

Its terminal summary has this form:

```text
total flows seen: 100, flows that reached 100 opcodes: 100, flows flagged: 100, output directory: /.../runs/YYYY-MM-DD/session_100__TIMESTAMP
```

This shows the format using the repository's current sample data; counts and
the timestamp depend on the input PCAP and execution time.

### Detector output CSV

`openvpn.csv` has these columns:

```text
proto,client_ip,client_port,server_ip,server_port,n_eval,unique_opcodes,first_opcode,last_opcode,opcode_sequence
```

Example row (the opcode sequence is shortened here only for readability):

```csv
proto,client_ip,client_port,server_ip,server_port,n_eval,unique_opcodes,first_opcode,last_opcode,opcode_sequence
UDP,10.184.106.251,42741,10.208.23.185,1194,100,4,7,9,7|4|4|5|...|9
```

Important meanings:

- `client_*` is the first-seen sender for the direction-normalized flow.
- `server_*` is the opposite endpoint; these labels do not independently prove
  application roles.
- `n_eval` is the 100-opcode decision window.
- `unique_opcodes` is the number of distinct opcodes in that window.
- `first_opcode` and `last_opcode` are the first and 100th opcodes.
- `opcode_sequence` contains all 100 opcodes separated by `|`.

TCP streams are reassembled per direction before length-prefixed OpenVPN
records are parsed. UDP contributes at most one opcode per non-empty datagram.
After a flow reaches the decision window, later packets for that flow are
ignored. Flows that do not reach 100 opcodes do not appear in `openvpn.csv`.

## Generate or rerun a flow summary

To print a summary for an existing detector CSV:

```bash
.venv/bin/python pipeline/flow_summary.py \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv"
```

To save the same terminal output to a text file:

```bash
.venv/bin/python pipeline/flow_summary.py \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv" \
  > flow_summary.txt
```

The summary always includes a `CONTROLLED TRAFFIC` section for flows involving
the configured controlled server `10.208.23.185`, followed by the associated
client IPs and their flow counts. The command also supports role-neutral IP
inspection, user-assigned endpoint roles, port filters, detailed tables, and
endpoint CSV exports, documented below.

## Combine session PCAPs

`combine_session_pcaps.py` discovers `session_N` directories, sorts them by
numeric session ID, appends each `client.pcap` in that exact order, and writes
a JSON manifest. The combined capture is stored in the output directory's
`pcap/` subdirectory.

Usage:

```text
python pipeline/combine_session_pcaps.py SOURCE_DIRECTORY OUTPUT_DIRECTORY [OPTIONS]
```

Example:

```bash
.venv/bin/python pipeline/combine_session_pcaps.py \
  /path/to/sessions \
  /path/to/combined_dataset
```

Custom input and output names:

```bash
.venv/bin/python pipeline/combine_session_pcaps.py \
  /path/to/sessions \
  /path/to/combined_dataset \
  --input-name client.pcap \
  --output-name combined_sessions.pcap
```

Existing output files are protected by default. Pass `--overwrite` to replace
them, or use `--help` to see all options. Wireshark's `mergecap` and `capinfos`
command-line tools must be installed for this utility.

## Flow-summary filters and exports

`flow_summary.py` analyzes the flow-level CSV files produced by this project.
It prints raw counts and tables to the terminal. It does not require pandas or
any other third-party Python package.

The script treats the CSV's `client_*` and `server_*` columns as neutral
endpoints unless you explicitly assign roles with `--client-ip` or
`--destination-ip`. Role-based filters still match either side of a CSV row.

Show every supported argument:

```bash
.venv/bin/python pipeline/flow_summary.py --help
```

The module form is equivalent:

```bash
.venv/bin/python -m pipeline.flow_summary \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv"
```

## Common commands

### Analyze the complete CSV

```bash
python3 pipeline/flow_summary.py INPUT.csv
```

Example:

```bash
python3 pipeline/flow_summary.py \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv"
```

This reports total and unique flows, repeated flow records, exact duplicate
rows, TCP/UDP counts, packet counts, unique IPs, unique IP pairs, source PCAP
count, and the flow-opening time range.

### Analyze any IP without assigning a role

```bash
python3 pipeline/flow_summary.py INPUT.csv --ip IP_ADDRESS
```

Example:

```bash
python3 pipeline/flow_summary.py \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv" \
  --ip 10.184.106.251
```

The IP can appear in either endpoint column. The opposite endpoint is called a
peer; no client, destination, inbound, or outbound role is assumed.

### Analyze a user-declared client IP

```bash
python3 pipeline/flow_summary.py INPUT.csv --client-ip CLIENT_IP
```

Example:

```bash
python3 pipeline/flow_summary.py \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv" \
  --client-ip 10.184.106.251
```

The supplied IP is treated as the client because you assigned that role. The
opposite endpoint is treated as a destination. Matching does not depend on
which CSV column contains the client IP.

### Analyze a user-declared destination IP

```bash
python3 pipeline/flow_summary.py INPUT.csv \
  --destination-ip DESTINATION_IP
```

Example:

```bash
python3 pipeline/flow_summary.py \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv" \
  --destination-ip 10.208.23.185
```

The supplied IP is treated as the destination. Opposite endpoints are counted
as clients.

### Analyze traffic between a client and destination

```bash
python3 pipeline/flow_summary.py INPUT.csv \
  --client-ip CLIENT_IP \
  --destination-ip DESTINATION_IP
```

Example:

```bash
python3 pipeline/flow_summary.py \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv" \
  --client-ip 10.184.106.251 \
  --destination-ip 10.208.23.185
```

Both IPs can appear in either CSV endpoint column. The roles come from the
command arguments.

### Restrict the destination port

Use `--destination-port` with a client or destination filter:

```bash
python3 pipeline/flow_summary.py \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv" \
  --client-ip 10.184.106.251 \
  --destination-ip 10.208.23.185 \
  --destination-port 1194
```

You can also filter all destinations on one port for a known client:

```bash
python3 pipeline/flow_summary.py INPUT.csv \
  --client-ip 10.184.106.251 \
  --destination-port 1194
```

## Export endpoint lists

Endpoint exports always contain exactly two columns:

```csv
ip,port
10.208.23.185,1194
```

Entries are unique and numerically sorted by IP and port. TCP and UDP using the
same IP and port produce one CSV entry.

### Export destinations for a client

This command prints all destinations and saves the same list:

```bash
python3 pipeline/flow_summary.py \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv" \
  --client-ip 10.184.106.251 \
  --destinations-csv destinations.csv
```

`--destinations-csv` requires `--client-ip`.

### Export peers for a role-neutral IP

```bash
python3 pipeline/flow_summary.py \
  "$(cat runs/LATEST_RUN.txt)/openvpn.csv" \
  --ip 10.184.106.251 \
  --peers-csv peers.csv
```

`--peers-csv` requires `--ip`.

### Replace an existing endpoint CSV

The script refuses to overwrite an existing file unless `--force` is present:

```bash
python3 pipeline/flow_summary.py INPUT.csv \
  --client-ip 10.184.106.251 \
  --destinations-csv destinations.csv \
  --force
```

The input CSV can never be used as the output path, even with `--force`.

## Detailed raw tables

Add `--details` to the overall or filtered command:

```bash
python3 pipeline/flow_summary.py INPUT.csv --details
```

For details about one IP:

```bash
python3 pipeline/flow_summary.py INPUT.csv \
  --ip 10.184.106.251 \
  --details
```

Detailed mode adds these raw tables:

- Top 10 IP pairs by flow count
- Top 10 participating IP addresses
- Flow count per source PCAP
- Packet-count minimum, median, 95th percentile, and maximum
- Close-reason counts
- Largest gap between consecutive flow-opening timestamps
- Data-quality counters

When a filter is supplied, detailed traffic tables describe the matching
flows. Data-quality counters always describe the complete input CSV.

## Example output

Running the client-to-destination command on the current example data produces
the following main counts:

```text
OVERALL TRAFFIC
---------------
Total flow records           : 98
Unique flow keys             : 98
Repeated flow records        : 0
Exact duplicate rows         : 0
TCP flows                    : 38 (38.8%)
UDP flows                    : 60 (61.2%)
Packets collected            : 10,259
Unique IP addresses          : 25
Unique IP pairs (IP only)    : 20
Source PCAP files            : 5
First flow opened            : 2026-10-18 23:21:10 UTC
Last flow opened             : 2026-10-19 03:00:08 UTC
Flow-opening time span       : 3h 38m 57.670s

CLIENT TO DESTINATION ANALYSIS
------------------------------
Client IP                    : 10.184.106.251
Destination IP               : 10.208.23.185
Destination port             : 1194
Matched flow records         : 62 (63.3%)
Unique flow keys             : 62
Repeated flow records        : 0
Exact duplicate rows         : 0
TCP flows                    : 31 (50.0%)
UDP flows                    : 31 (50.0%)
Packets collected            : 6,704
Unique destination IPs       : 1
Unique destination IP:ports  : 1
```

Filtered commands also print a `TRAFFIC OUTSIDE FILTER` section for comparison.

## Flow-count definitions

### Total flow records

The number of valid TCP/UDP CSV rows. The script assumes each valid row is one
detected flow record.

### Unique flow keys

A flow key contains:

```text
protocol + endpoint-1 IP:port + endpoint-2 IP:port
```

Endpoint order is ignored. These rows therefore share one flow key:

```text
TCP  10.0.0.1:50000 -> 10.0.0.2:443
TCP  10.0.0.2:443   -> 10.0.0.1:50000
```

### Repeated flow records

The number of records beyond the first occurrence of each flow key:

```text
repeated flow records = total flow records - unique flow keys
```

A repeated key is not automatically removed. A transport tuple can be reused
at different times, so repeated keys are not necessarily bad data.

### Exact duplicate rows

Additional CSV rows whose complete field values are identical. This is stricter
than a repeated flow key.

### Unique IP pairs

The number of unique IP-to-IP relationships. Ports, protocol, and endpoint
order are ignored. Many TCP/UDP flows between the same two IP addresses count
as one IP pair.

## Timing and packet meanings

`Flow-opening time span` is the difference between the earliest and latest
valid `open_utc` values. It is not the duration of an individual connection or
the exact duration of a PCAP because the CSV has no flow-closing timestamp.

`Packets collected` is the sum of the CSV's `packets_collected` values. Check
the `CLOSE REASONS` table in detailed mode before treating it as complete flow
volume. For example, `window_full` can mean collection stopped at a configured
window limit.

## Expected CSV columns

Required columns:

```text
proto
client_ip
client_port
server_ip
server_port
```

Optional columns used when available:

```text
packets_collected
open_utc
pcap_file
close_reason
```

Only TCP and UDP rows are analyzed. Unsupported protocols and malformed
endpoint rows are skipped and counted in `DATA QUALITY`.

## Argument rules

- `--ip` cannot be combined with `--client-ip` or `--destination-ip`.
- `--client-ip` and `--destination-ip` can be used alone or together.
- Client and destination IPs must be different when both are supplied.
- `--destination-port` requires a client or destination filter.
- `--destinations-csv` requires `--client-ip`.
- `--peers-csv` requires `--ip`.
- `--force` requires an endpoint CSV option.
- Valid ports are from `0` through `65535`.
- IPv4 and IPv6 addresses are supported.

## Troubleshooting

### Input file not found

Run the command from the repository root or provide an absolute CSV path:

```bash
python3 pipeline/flow_summary.py \
  /absolute/path/to/openvpn.csv
```

### Output file already exists

Choose a different filename or add `--force` if replacement is intentional.

### Matched flow count is zero

Confirm the address exists in either endpoint column:

```bash
rg '10\.184\.106\.251' INPUT.csv
```

Then check whether an optional destination IP or port made the filter too
restrictive.

### Missing timing or packet values

The flow still counts when optional `open_utc` or `packets_collected` data is
missing or invalid. The relevant metric becomes `N/A` or reports the number of
unavailable rows, and detailed mode shows the data-quality count.
