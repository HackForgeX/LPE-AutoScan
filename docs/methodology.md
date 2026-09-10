# LPE-AutoScan Assessment & Security Methodology

## Core Principles

1. **Detection Only / Zero Payload Guarantee**:
   LPE-AutoScan never attempts payload execution, kernel exploitation, binary hijacking, file modification, or privilege escalation. It functions strictly as an automated blue-team configuration auditor.

2. **Least Privilege & Safe Subprocess Invocations**:
   All subprocess calls are executed using parameter lists (without `shell=True`), strict execution timeouts (3-5 seconds), and graceful fallback handling when tools (such as `getcap`) are absent.

3. **False Positive Reduction**:
   The engine avoids flagging standard baseline system binaries by maintaining an explicit system allowlist for expected SUID binaries (`/usr/bin/sudo`, `/usr/bin/passwd`, `/usr/bin/su`). Only non-allowlisted binaries or those mapped to GTFOBins entries trigger alerts.

## Module Detection Mechanics

| Module | Inspection Strategy | Risk Condition |
|---|---|---|
| **System Info** | Inspects `os.getuid()`, `os.environ['PATH']` | Writable or relative (`.`) PATH entries |
| **Users & Groups** | Parses `/etc/passwd`, `/etc/group` | UID 0 non-root accounts; membership in `docker`, `lxd`, `disk`, `shadow` |
| **SUID / SGID** | Recursively scans `/bin`, `/usr/bin`, `/sbin`, `/opt` | GTFOBins binaries with SUID bit or non-allowlisted SUID files |
| **Permissions** | Inspects `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | World-writable critical files or world-readable shadow file |
| **Sudo Rules** | Parses `/etc/sudoers` and `sudo -l -n` output | `NOPASSWD: ALL`, NOPASSWD dangerous binaries, wildcard `*` rules |
| **Cron Tasks** | Audits `/etc/crontab`, `/etc/cron.*`, spool files | Privileged cron jobs executing user-writable scripts |
| **Systemd Services**| Inspects `.service` unit files in `/etc/systemd/system` | Privileged services executing user-writable binaries |
| **Capabilities** | Runs `getcap -r` across system binary paths | Elevated file capabilities (`cap_setuid`, `cap_dac_override`) |
| **SSH Security** | Inspects `/etc/ssh/sshd_config` and `authorized_keys` | `PermitRootLogin yes`, `PermitEmptyPasswords yes`, writable key files |
| **Docker / Container**| Inspects `/var/run/docker.sock` and cgroups | Unprivileged user access to Docker daemon API socket |
| **Kernel CVE** | Matches `platform.release()` against `cve_db.json` | Kernel version falling within known CVE vulnerability window |
