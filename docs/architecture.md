# LPE-AutoScan Architecture Documentation

## Overview

LPE-AutoScan is designed as a defensive, detection-only security assessment engine written in Python 3. It provides non-intrusive local privilege escalation enumeration, misconfiguration analysis, GTFOBins reference mapping, kernel CVE correlation, and multi-format report generation (Terminal, JSON, HTML).

```
                            ┌────────────────────────┐
                            │   LPE-AutoScan CLI     │
                            └───────────┬────────────┘
                                        │
                                        ▼
                            ┌────────────────────────┐
                            │    Analysis Engine     │
                            └───────────┬────────────┘
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
  ┌────────────────────┐     ┌────────────────────┐     ┌────────────────────┐
  │  Scanner Modules   │     │  GTFOBins Database │     │   Kernel CVE DB    │
  │(SysInfo, Sudo, etc)│     │  (gtfobins.json)   │     │    (cve_db.json)   │
  └──────────┬─────────┘     └──────────┬─────────┘     └──────────┬─────────┘
             │                          │                          │
             └──────────────────────────┼──────────────────────────┘
                                        │
                                        ▼
                            ┌────────────────────────┐
                            │ Normalization & Risk   │
                            │    Scoring Engine      │
                            └───────────┬────────────┘
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
  ┌────────────────────┐     ┌────────────────────┐     ┌────────────────────┐
  │  Terminal Reporter │     │   JSON Reporter    │     │   HTML Reporter    │
  └────────────────────┘     └────────────────────┘     └────────────────────┘
```

## Data Pipeline

1. **Enumeration Phase**:
   Each scanner module inherits from `BaseScanner` and executes isolated, read-only system queries (inspecting permissions, environment variables, system files, systemd units, cron spools, POSIX capabilities, and kernel release strings).

2. **GTFOBins & CVE Reference Mapping**:
   Identified SUID binaries and kernel version strings are correlated against local JSON databases (`gtfobins.json` and `cve_db.json`). Exploit commands are explicitly excluded; only reference documentation, impact, and mitigation guidance are mapped.

3. **Normalization & Risk Engine**:
   Findings are converted to standard `Finding` data instances. The `AnalysisEngine` filters duplicates, applies minimum severity thresholds (`--severity`), ranks findings by risk level (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`), and attaches confidence ratings (`HIGH`, `MEDIUM`, `LOW`).

4. **Reporting Phase**:
   Findings are passed to the selected reporter (`TerminalReporter`, `JsonReporter`, `HtmlReporter`) to format output.

## Core Data Schema (`Finding`)

| Field | Type | Description |
|---|---|---|
| `finding_id` | `str` | Unique finding identifier (e.g. `SUDO-NOPASSWD-ALL`) |
| `category` | `Category` | Module classification enum |
| `title` | `str` | High-level summary title |
| `severity` | `Severity` | Risk rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |
| `confidence` | `Confidence` | Evidence confidence (`HIGH`, `MEDIUM`, `LOW`) |
| `description` | `str` | Clear explanation of the detected condition |
| `evidence` | `List[str]` | Empirical evidence collected from system state |
| `impact` | `str` | Potential security risk or escalation vector |
| `exploitation_possible` | `bool` | True if evidence supports direct exploitability |
| `references` | `List[str]` | Documentation links (GTFOBins, MITRE ATT&CK, NVD) |
| `mitigation` | `str` | Blue-team remediation instructions |
| `detected_at` | `str` | ISO 8601 UTC timestamp |
