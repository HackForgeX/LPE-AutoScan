# LPE-AutoScan

### Linux Privilege Escalation Detection & Assessment Toolkit

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.0.0-green)](https://github.com/HackForgeX/lpe-autoscan)
[![Tests](https://img.shields.io/badge/tests-12%20passed-brightgreen)](https://github.com/HackForgeX/lpe-autoscan)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](https://www.linux.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

LPE-AutoScan is a **defensive, detection-only Linux security assessment
framework** written in Python 3.

It automatically enumerates local security configurations, identifies
potential Linux privilege-escalation risk factors, correlates findings with
security references such as GTFOBins and CVEs, assigns rule-based severity
and confidence levels, and generates structured Terminal, JSON, and HTML
reports.

---

## Table of Contents

- [Overview](#overview)
- [Project Status](#project-status)
- [Key Features](#key-features)
- [Safety and Non-Exploitation Policy](#safety-and-non-exploitation-policy)
- [Disclaimer](#disclaimer)
- [Detection Modules](#detection-modules)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [Example Terminal Output](#example-terminal-output)
- [Testing](#testing)
- [Documentation](#documentation)
- [Practical Testing](#practical-testing)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Overview

Linux privilege escalation occurs when a local user is able to obtain
privileges beyond those originally assigned to the account.

Finding privilege-escalation weaknesses manually can require checking
multiple areas of a Linux system, including:

- SUID/SGID binaries
- File permissions
- Sudo configuration
- Cron jobs
- Systemd services
- Linux capabilities
- User and group memberships
- SSH configuration
- Container environments
- Kernel versions and known vulnerabilities

LPE-AutoScan automates this enumeration and assessment process.

The toolkit follows a **detection-first approach**: it identifies and
reports potentially dangerous configurations without attempting to exploit
them.

---

## Project Status

| Property | Value |
|---|---|
| Version | 1.0.0 |
| Status | Stable educational release |
| Language | Python 3 |
| Platform | Linux |
| Architecture | Modular scanner framework |
| Testing | Pytest |
| Output | Terminal / JSON / HTML |
| Security Model | Detection-only |

---

## Key Features

- Automated Linux security enumeration
- Modular scanner architecture
- SUID/SGID binary analysis
- Sudo configuration analysis
- Sensitive file permission checks
- Cron job inspection
- Systemd service analysis
- Linux capability analysis
- User and group enumeration
- SSH security checks
- Docker/container environment detection
- Kernel/CVE correlation
- GTFOBins reference mapping
- Rule-based severity scoring
- Confidence scoring
- Machine-readable JSON reports
- HTML executive reports
- Terminal-based security reports
- Unit testing with pytest
- Safe subprocess execution with timeouts
- Detection-only design

---

## Safety and Non-Exploitation Policy

> [!IMPORTANT]
> LPE-AutoScan is designed as a **detection-only security assessment
> toolkit**.

### Strict Detection-Only Guarantee

LPE-AutoScan:

- **Does NOT execute exploit payloads**
- **Does NOT execute shellcode**
- **Does NOT execute GTFOBins exploitation commands**
- **Does NOT execute kernel exploits**
- **Does NOT modify system configuration**
- **Does NOT modify `/etc/passwd`**
- **Does NOT modify `/etc/shadow`**
- **Does NOT modify `/etc/sudoers`**
- **Does NOT create or modify cron jobs**
- **Does NOT modify systemd services**
- **Does NOT change file permissions**
- Uses read-only inspection wherever possible
- Uses safe subprocess invocations with execution timeouts

The purpose of the project is to **identify and assess security weaknesses,
not exploit them**.

---

## Disclaimer

LPE-AutoScan is intended for:

- Authorized security assessments
- Defensive security research
- Cybersecurity education
- CTF/laboratory environments
- Controlled security testing
- Authorized compliance assessments

**Do not use this tool against systems for which you do not have explicit
authorization.**

The authors are not responsible for unauthorized or malicious use of this
software.

---

## Detection Modules

### 1. System Information

**Module:** `sysinfo`

Collects and evaluates:

- Operating system information
- Kernel version
- CPU architecture
- Current UID/GID
- PATH environment configuration
- Basic host security information

---

### 2. User and Group Analysis

**Module:** `users`

Checks:

- UID 0 accounts
- Interactive shell users
- Privileged group memberships
- Sensitive groups such as:

  - `sudo`
  - `wheel`
  - `docker`
  - `lxd`
  - `disk`
  - `shadow`

---

### 3. SUID/SGID Scanner

**Module:** `suid`

Discovers SUID/SGID binaries and:

- Compares binaries against an allowlist baseline
- Identifies potentially dangerous permissions
- Maps relevant binaries against GTFOBins references
- Produces security findings with severity and confidence

---

