# Shadow IT Package Detector

A Python proof of concept for identifying package-repository activity in existing logs, with separate read-only macOS and Windows installed-package inventory helpers. These scripts do not determine whether software is approved by your organisation.

## Requirements

- Python 3.9 or later for the full template; standard library only.
- For the macOS inventory helper, supported package managers must already be installed.
- No Feedly token is required to collect or analyse local data.

## Option 1: Analyse existing repository logs

```bash
python3 shadow-it-detector.py sample.csv
# Substitute your own CSV/TSV log file:
python3 shadow-it-detector.py /path/to/logfile.csv
```

Supported input is a CSV or tab-delimited file with a header. Recognised columns:

| Field | Accepted names |
|---|---|
| Timestamp | `timestamp`, `time` |
| User | `user`, `username` |
| Repository hostname | `host`, `sni`, `server_name` |
| Request URL | `url`, `request`, `uri` |
| Command line | `command_line`, `process`, `cmd` |

Missing fields are allowed. The parser recognises PyPI and npm hostnames and uses URL/command heuristics to extract package names. It prints a summary and writes `repo_findings.csv` in the current working directory when findings exist. That output is overwritten on subsequent successful runs; no new output is written when there are no findings. Archive each run separately to avoid using stale output.

This template does not collect traffic or start osquery, dnsmasq or tcpdump. Convert source logs to the documented columns before using it. Ordinary DNS logs and encrypted packet captures generally reveal domains rather than package URL paths; a repository contact may therefore have no package name.

### Parser limitations

- CSV/TSV input and CSV output only; JSONL is not implemented.
- Heuristic extraction can produce false positives and miss packages, especially scoped npm packages, encoded URLs, pip3 commands, command options and requirements files.
- Package versions are not retained as structured fields. Download/install activity does not prove a package remains installed.
- Input errors are currently printed and can look like an empty result; check the console log rather than interpreting no findings as a successful clean scan.
- The file is read incrementally but findings are retained in memory.

## Option 2: Inventory installed packages on macOS

```bash
python3 inventory_mac.py
```

The helper uses read-only package-manager queries and local application metadata. It does not install, update or remove software. It collects Homebrew formulae/casks, global npm packages, Python packages from selected interpreters, local Ruby gems, Conda packages and top-level apps in `/Applications` and `~/Applications`.

Outputs are written beside the helper in `inventory/`:

| File | Contents |
|---|---|
| `packages.csv` | Ecosystem, name, reported version and source |
| `packages.json` | Inventory, collection timestamp and limitations |
| `raw.json` | Raw package-manager output and collection errors |

Capture a run summary with:

```bash
python3 inventory_mac.py > scan.log 2>&1
```

Inspect `incomplete_sources` in `packages.json` and errors in `raw.json`. If Conda cannot execute, the helper attempts to recover package records from local `conda-meta` files. The errors remain recorded so the partial coverage is visible.

Coverage is partial: project dependencies, unlisted virtual environments, containers, nested apps, other accounts and packages installed outside these sources may be absent. Records from different sources may overlap. It is not a complete software bill of materials or historical installation log. Output files are overwritten each run; archive them before the next scan.

## Option 3: Inventory installed packages on Windows

Requires Python 3.9+; no third-party Python packages or administrator privileges are required. Run from PowerShell or Command Prompt:

```powershell
py -3 inventory_windows.py
```

If the Python launcher is unavailable, use `python inventory_windows.py` with your installed Python interpreter.

The helper reads application names and versions from the current-user and machine-wide Windows uninstall registry (32-bit and 64-bit views), Python packages in the interpreter running the script, global npm packages if npm is on PATH, and discoverable Conda environments if Conda is on PATH. It does not install, update, uninstall or repair software. It does not use `Win32_Product`.

Each run creates a timestamped folder under `inventory/windows/` containing `packages.csv`, `packages.json`, `raw.json` and `scan.log`. The CSV uses the same `ecosystem,name,version,source` columns as the Mac helper. Review `incomplete_sources` and `skipped_sources`: a missing package manager is recorded as skipped; query errors are recorded as incomplete. Exit codes are 0 for collection without recorded errors, 1 for an unsupported OS, and 2 for partial collection with errors. A zero exit code does not imply complete coverage or absence of vulnerabilities.

Coverage is partial: Microsoft Store apps, portable apps, project dependencies, other Python interpreters and virtual environments, WSL, containers and other users may be absent. Registry records may be stale or lack versions. Entries from different sources can overlap. This is an installed-package inventory, not a historical installation/network log or a Feedly assessment.

The script contains no personal inventory or credentials. Its generated reports can include usernames and local paths; review before sharing and exclude `inventory/` from GitHub.

Validation note: syntax, command construction and report generation were checked with simulated inputs on macOS. A live Windows run is still required to verify collection on your target machine.

## Analyse the results with Feedly

These scripts do not call Feedly or include a scheduler. Take `packages.csv` to an assistant with an authorised Feedly Threat Graph MCP connection, or build an API integration using your Feedly account's supported endpoints and permissions.

Suggested prompt:

> Use the connected Feedly Threat Graph MCP to investigate this package inventory for known vulnerabilities and exploitation reports. Match package ecosystem and exact installed version where evidence permits. Distinguish confirmed affected versions from uncertain product matches, and public exploit availability from observed active exploitation. Return package, installed version, CVE, exploitation status, evidence links, remediation and unknowns. Absence of Feedly coverage is not proof of safety. Do not infer version applicability from a package-name match alone.

Version-aware advisory matching may require an additional vulnerability data source. Log-derived names without versions are discovery leads rather than confirmed vulnerable installations.

## Periodic checks

Before scheduling, validate coverage, preserve timestamped outputs and handle partial/failed collections explicitly. Compare inventories and exploitation intelligence across runs; a package can become newly exploited even if its version has not changed. Configure scheduling separately for your environment. No automation is created by running the scripts.

## Data handling

Reports can contain usernames, local paths, URLs and command-line arguments, including sensitive data present in source logs. Review and redact before uploading or sharing. No live inventory or credentials are included in this template.

## Origin and changes

Based on the Feedly sample at https://github.com/feedly/sample-customer-scripts/tree/main/python/Shadow-IT-Detector . The detector's hard-coded test argument override has been removed and usage text now matches its filename. This documentation reflects the implemented CSV/TSV behaviour. The macOS inventory helper is a separate addition.
