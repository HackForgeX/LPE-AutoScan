"""
Systemd Services Analysis Scanner.
Audits systemd service unit configurations for privileged services referencing writable binaries or scripts in ExecStart/ExecStartPre.
"""

import os
import stat
from typing import List, Tuple
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class SystemdScanner(BaseScanner):
    name = "systemd"
    category = Category.SYSTEMD
    description = "Audit systemd service unit configurations for insecure binary paths"

    SYSTEMD_UNIT_DIRS = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        current_uid = os.getuid()

        units = self._collect_service_units()

        for unit_name, unit_path, user, exec_starts in units:
            if user not in ["root", "0", ""] and not user.startswith("User="):
                # Service runs as non-privileged unprivileged user
                continue

            for exec_line in exec_starts:
                binary_path = self._extract_binary_path(exec_line)
                if not binary_path or not os.path.exists(binary_path):
                    continue

                try:
                    st = os.stat(binary_path)
                    mode = st.st_mode

                    if (mode & stat.S_IWOTH) or (os.access(binary_path, os.W_OK) and current_uid != 0):
                        findings.append(
                            Finding(
                                finding_id=f"SYSTEMD-WRITABLE-EXEC",
                                category=self.category,
                                title=f"Privileged Systemd Service Executes Writable Binary: '{binary_path}'",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                description=f"The systemd service '{unit_name}' runs as root and executes '{binary_path}' which is writable by unprivileged users.",
                                evidence=[f"Service Unit: {unit_path}", f"User: {user or 'root (default)'}", f"ExecLine: {exec_line}", f"Writable Binary: {binary_path}"],
                                impact="Unprivileged users can replace or modify the target service executable to obtain root code execution when the service runs/restarts.",
                                exploitation_possible=True,
                                references=["https://attack.mitre.org/techniques/T1543/002/"],
                                mitigation=f"Restrict permissions on binary: chown root:root {binary_path} && chmod 755 {binary_path}"
                            )
                        )
                except (PermissionError, FileNotFoundError):
                    continue

        return findings

    def _collect_service_units(self) -> List[Tuple[str, str, str, List[str]]]:
        units = []

        for udir in self.SYSTEMD_UNIT_DIRS:
            if not os.path.exists(udir) or not os.access(udir, os.R_OK):
                continue

            try:
                for filename in os.listdir(udir):
                    if filename.endswith(".service"):
                        filepath = os.path.join(udir, filename)
                        if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                            user = ""
                            exec_starts = []
                            with open(filepath, "r", errors="ignore") as f:
                                for line in f:
                                    line_s = line.strip()
                                    if line_s.startswith("User="):
                                        user = line_s.split("=", 1)[1].strip()
                                    elif line_s.startswith("ExecStart=") or line_s.startswith("ExecStartPre="):
                                        exec_starts.append(line_s.split("=", 1)[1].strip())
                            if exec_starts:
                                units.append((filename, filepath, user, exec_starts))
            except Exception:
                pass

        return units

    def _extract_binary_path(self, exec_line: str) -> str:
        tokens = exec_line.split()
        for tok in tokens:
            tok_clean = tok.lstrip("-@+:").strip("'\"")
            if tok_clean.startswith("/") and os.path.isabs(tok_clean):
                return tok_clean
        return ""
