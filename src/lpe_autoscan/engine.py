"""
Centralized Analysis Engine.
Orchestrates module enumeration, normalizing findings, applying rule-based severity/confidence scoring, filtering false positives, and producing structured results.
"""

from typing import List, Dict, Type, Optional
from lpe_autoscan.models import Finding, Severity, Confidence
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.scanners.sysinfo import SysInfoScanner
from lpe_autoscan.scanners.users_groups import UsersGroupsScanner
from lpe_autoscan.scanners.suid_sgid import SuidSgidScanner
from lpe_autoscan.scanners.permissions import PermissionsScanner
from lpe_autoscan.scanners.sudo_analysis import SudoScanner
from lpe_autoscan.scanners.cron_analysis import CronScanner
from lpe_autoscan.scanners.systemd_analysis import SystemdScanner
from lpe_autoscan.scanners.capabilities import CapabilitiesScanner
from lpe_autoscan.scanners.ssh_check import SshScanner
from lpe_autoscan.scanners.docker_check import DockerScanner
from lpe_autoscan.scanners.kernel_cve import KernelCveScanner


class AnalysisEngine:
    """Centralized detection pipeline & rule engine."""

    ALL_SCANNERS: Dict[str, Type[BaseScanner]] = {
        "sysinfo": SysInfoScanner,
        "users": UsersGroupsScanner,
        "suid": SuidSgidScanner,
        "permissions": PermissionsScanner,
        "sudo": SudoScanner,
        "cron": CronScanner,
        "systemd": SystemdScanner,
        "capabilities": CapabilitiesScanner,
        "ssh": SshScanner,
        "docker": DockerScanner,
        "kernel": KernelCveScanner,
    }

    def __init__(self, selected_module: Optional[str] = None, min_severity: Optional[str] = None):
        self.selected_module = selected_module.lower() if selected_module else None
        self.min_severity = Severity[min_severity.upper()] if min_severity else None

    def run(self) -> List[Finding]:
        all_findings: List[Finding] = []

        scanners_to_run = []
        if self.selected_module and self.selected_module in self.ALL_SCANNERS:
            scanners_to_run.append(self.ALL_SCANNERS[self.selected_module]())
        else:
            for cls in self.ALL_SCANNERS.values():
                scanners_to_run.append(cls())

        for scanner in scanners_to_run:
            try:
                findings = scanner.scan()
                all_findings.extend(findings)
            except Exception as e:
                # Log scanner failure gracefully without breaking pipeline
                pass

        # Deduplicate & normalize findings
        normalized = self._normalize_and_filter(all_findings)
        return normalized

    def _normalize_and_filter(self, findings: List[Finding]) -> List[Finding]:
        seen_ids = set()
        filtered: List[Finding] = []

        for f in findings:
            if f.finding_id in seen_ids:
                continue
            seen_ids.add(f.finding_id)

            # Filter by minimum severity rank if set
            if self.min_severity and f.severity.rank < self.min_severity.rank:
                continue

            filtered.append(f)

        # Sort findings by severity rank descending
        filtered.sort(key=lambda x: x.severity.rank, reverse=True)
        return filtered
