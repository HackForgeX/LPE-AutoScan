"""
Base Reporter abstract interface.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from lpe_autoscan.models import Finding


class BaseReporter(ABC):
    """Abstract interface for LPE-AutoScan report generators."""

    @abstractmethod
    def generate(self, findings: List[Finding], output_path: Optional[str] = None) -> str:
        """Generate formatted report string and optionally write to output file."""
        pass
