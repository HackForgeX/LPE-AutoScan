"""
Tests for Phase 1 data models and sysinfo scanner.
"""

from lpe_autoscan.models import Finding, Severity, Confidence, Category
from lpe_autoscan.scanners.sysinfo import SysInfoScanner


def test_finding_to_dict():
    finding = Finding(
        finding_id="TEST-001",
        category=Category.SYSINFO,
        title="Test Finding",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Test description",
        evidence=["Evidence 1"],
        impact="Test impact",
        exploitation_possible=False,
        references=["https://example.com"],
        mitigation="Test mitigation"
    )
    d = finding.to_dict()
    assert d["finding_id"] == "TEST-001"
    assert d["severity"] == "HIGH"
    assert d["confidence"] == "MEDIUM"
    assert d["category"] == "system_information"


def test_sysinfo_scanner():
    scanner = SysInfoScanner()
    info = scanner.collect_info()
    assert "username" in info
    assert "uid" in info
    assert "kernel_version" in info

    findings = scanner.scan()
    assert isinstance(findings, list)
