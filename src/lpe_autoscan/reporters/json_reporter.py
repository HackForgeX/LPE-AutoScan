"""
JSON Report Exporter module.
Generates machine-readable JSON security scan results.
"""

import json
from typing import List, Optional
from datetime import datetime, timezone
from lpe_autoscan.models import Finding
from lpe_autoscan.reporters.base import BaseReporter
from lpe_autoscan import __version__


class JsonReporter(BaseReporter):
    """Generates schema-compliant JSON security reports."""

    def generate(self, findings: List[Finding], output_path: Optional[str] = None) -> str:
        report_data = {
            "meta": {
                "tool": "LPE-AutoScan",
                "version": __version__,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_findings": len(findings),
            },
            "findings": [f.to_dict() for f in findings],
        }

        report_json = json.dumps(report_data, indent=2)

        if output_path:
            with open(output_path, "w") as f:
                f.write(report_json)

        return report_json
