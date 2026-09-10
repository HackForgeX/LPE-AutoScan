"""
Data models and schemas for LPE-AutoScan findings, severity levels, and confidence ratings.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        ranks = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1
        }
        return ranks.get(self.value, 0)


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Category(str, Enum):
    SYSINFO = "system_information"
    USERS_GROUPS = "users_and_groups"
    SUID_SGID = "suid_sgid_binaries"
    PERMISSIONS = "file_permissions"
    SUDO = "sudo_configuration"
    CRON = "scheduled_tasks"
    SYSTEMD = "systemd_services"
    CAPABILITIES = "linux_capabilities"
    SSH = "ssh_security"
    DOCKER = "container_security"
    KERNEL_CVE = "kernel_vulnerabilities"


@dataclass
class Finding:
    finding_id: str
    category: Category
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: List[str]
    impact: str
    exploitation_possible: bool
    references: List[str]
    mitigation: str
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        data["category"] = self.category.value
        return data
