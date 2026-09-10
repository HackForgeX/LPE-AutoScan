# LPE-AutoScan Controlled Test Lab & Unit Testing Guide

## Test Strategy

LPE-AutoScan employs a dual testing strategy:
1. **Automated Unit Testing with Pytest**:
   All scanner modules, analysis engine logic, data models, and reporters are unit-tested using mocked filesystem calls (`unittest.mock`), mocked `os.stat`, mocked subprocess outputs, and mocked user databases. This guarantees tests execute safely without altering system state or requiring root privileges.

2. **Controlled Linux Security Test Lab**:
   For integration testing in authorized lab environments (e.g., Docker containers or test VMs), specific misconfiguration test cases can be verified.

## Mock Test Fixtures Covered in `tests/test_scanners.py`

1. **SUID Finding Fixture**: Mocks `/usr/bin/find` with SUID bit set; verifies `SUID-GTFO-FIND` detection.
2. **SGID Finding Fixture**: Mocks custom binary in `/opt`; verifies `SUID-UNCOMMON` detection.
3. **Writable Privileged Script Fixture**: Mocks world-writable `/etc/passwd`; verifies `PERM-WW-PASSWD` critical alert.
4. **Unsafe Cron Entry Fixture**: Mocks root cron task executing `/opt/backup.sh` (writable by unprivileged user); verifies `CRON-WRITABLE-SCRIPT`.
5. **Unsafe Systemd Reference Fixture**: Mocks root service executing `/usr/local/bin/daemon` (writable); verifies `SYSTEMD-WRITABLE-EXEC`.
6. **Risky Sudo Rule Fixture**: Mocks `NOPASSWD: ALL` sudoers rule; verifies `SUDO-NOPASSWD-ALL`.
7. **Suspicious Capability Fixture**: Mocks `getcap` output with `cap_setuid`; verifies `CAP-CAP_SETUID`.
8. **Kernel / CVE Match Fixture**: Mocks Linux kernel release `5.10.0-8-amd64`; verifies Dirty Pipe `CVE-2022-0847` match with `MEDIUM` confidence.
9. **Safe Baseline Configuration Fixture**: Mocks normal user state without misconfigurations; verifies zero critical findings.
10. **Reporters Fixture**: Verifies Terminal text summary, JSON export, and HTML report output generation.

## Running Tests

Execute pytest from project root:

```bash
cd /home/kali/Downloads/project/lpe-tool
PYTHONPATH=src python3 -m pytest -v
```
