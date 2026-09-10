"""
Base scanner interface for LPE-AutoScan modules.
"""

from abc import ABC, abstractmethod
from typing import List
from lpe_autoscan.models import Finding, Category


class BaseScanner(ABC):
    """Abstract base class for all privilege escalation detection modules."""

    name: str = "base_scanner"
    category: Category = Category.SYSINFO
    description: str = "Base scanner interface"

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Execute read-only security enumeration and return a list of findings."""
        pass
