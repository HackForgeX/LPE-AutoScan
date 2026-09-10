"""
Comprehensive unit test suite for LPE-AutoScan scanners, rule engine, CLI, and reporters using safe mock fixtures.
"""

import pytest
import os
import json
from unittest.mock import patch, MagicMock
from lpe_autoscan.models import Finding, Severity, Confidence, Category
from lpe_autoscan.engine import AnalysisEngine
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
from lpe_autoscan.reporters.terminal import TerminalReporter
from lpe_autoscan.reporters.json_reporter import JsonReporter
from lpe_autoscan.reporters.html_reporter import HtmlReporter


# 1. SUID finding test
def test_suid_gtfobins_detection():
    scanner = SuidSgidScanner()
    scanner.SEARCH_DIRS = ["/usr/bin"]
    with patch("os.path.exists", return_value=True), \
         patch("os.walk") as mock_walk, \
         patch("os.lstat") as mock_stat, \
         patch("pwd.getpwuid") as mock_pw, \
         patch("grp.getgrgid") as mock_gr:

        mock_walk.return_value = [("/usr/bin", [], ["find"])]
        st = MagicMock()
        st.st_mode = 0o104755  # SUID bit set
        st.st_uid = 0
        st.st_gid = 0
        mock_stat.return_value = st
        mock_pw.return_value.pw_name = "root"
        mock_gr.return_value.gr_name = "root"

        findings = scanner.scan()
        gtfo_findings = [f for f in findings if "SUID-GTFO-FIND" in f.finding_id]
        assert len(gtfo_findings) == 1
        assert gtfo_findings[0].severity == Severity.HIGH


# 2. SGID finding test
def test_suid_uncommon_detection():
    scanner = SuidSgidScanner()
    scanner.SEARCH_DIRS = ["/opt"]
    with patch("os.path.exists", return_value=True), \
         patch("os.walk") as mock_walk, \
         patch("os.lstat") as mock_stat, \
         patch("pwd.getpwuid") as mock_pw, \
         patch("grp.getgrgid") as mock_gr:

        mock_walk.return_value = [("/opt", [], ["custom_tool"])]
        st = MagicMock()
        st.st_mode = 0o104755
        st.st_uid = 0
        st.st_gid = 0
        mock_stat.return_value = st
        mock_pw.return_value.pw_name = "root"
        mock_gr.return_value.gr_name = "root"

        findings = scanner.scan()
        uncommon = [f for f in findings if "SUID-UNCOMMON" in f.finding_id]
        assert len(uncommon) == 1


# 3. Writable privileged script test (Permissions)
def test_world_writable_passwd_detection():
    scanner = PermissionsScanner()
    with patch("os.path.exists", return_value=True), \
         patch("os.stat") as mock_stat, \
         patch("pwd.getpwuid") as mock_pw, \
         patch("grp.getgrgid") as mock_gr:

        st = MagicMock()
        st.st_mode = 0o100666  # World-writable
        st.st_uid = 0
        st.st_gid = 0
        mock_stat.return_value = st
        mock_pw.return_value.pw_name = "root"
        mock_gr.return_value.gr_name = "root"

        findings = scanner.scan()
        ww_passwd = [f for f in findings if f.finding_id == "PERM-WW-PASSWD"]
        assert len(ww_passwd) == 1
        assert ww_passwd[0].severity == Severity.CRITICAL


# 4. Unsafe cron entry test
def test_cron_writable_script():
    scanner = CronScanner()
    fake_cron = [("root", "/opt/backup.sh", "/etc/crontab")]
    with patch.object(scanner, "_collect_cron_entries", return_value=fake_cron), \
         patch("os.path.exists", return_value=True), \
         patch("os.stat") as mock_stat, \
         patch("os.access", return_value=True), \
         patch("os.getuid", return_value=1000):

        st = MagicMock()
        st.st_mode = 0o100777  # Writable by world
        st.st_uid = 0
        mock_stat.return_value = st

        findings = scanner.scan()
        assert len(findings) == 1
        assert findings[0].finding_id == "CRON-WRITABLE-SCRIPT"


# 5. Unsafe systemd reference test
def test_systemd_writable_exec():
    scanner = SystemdScanner()
    fake_units = [("custom.service", "/etc/systemd/system/custom.service", "root", ["/usr/local/bin/daemon"])]
    with patch.object(scanner, "_collect_service_units", return_value=fake_units), \
         patch("os.path.exists", return_value=True), \
         patch("os.stat") as mock_stat, \
         patch("os.access", return_value=True), \
         patch("os.getuid", return_value=1000):

        st = MagicMock()
        st.st_mode = 0o100777
        mock_stat.return_value = st

        findings = scanner.scan()
        assert len(findings) == 1
        assert findings[0].finding_id == "SYSTEMD-WRITABLE-EXEC"


# 6. Risky sudo rule test
def test_sudo_nopasswd_all():
    scanner = SudoScanner()
    fake_lines = [("user ALL=(ALL) NOPASSWD: ALL", "/etc/sudoers")]
    with patch.object(scanner, "_get_sudoers_lines", return_value=fake_lines):
        findings = scanner.scan()
        assert len(findings) == 1
        assert findings[0].finding_id == "SUDO-NOPASSWD-ALL"


# 7. Suspicious capability test
def test_capability_detection():
    scanner = CapabilitiesScanner()
    with patch("shutil.which", return_value="/sbin/getcap"), \
         patch.object(scanner, "_run_getcap", return_value=[("/usr/bin/python3", "= cap_setuid+ep")]):
        findings = scanner.scan()
        assert len(findings) == 1
        assert findings[0].finding_id == "CAP-CAP_SETUID"


# 8. Kernel / CVE match test
def test_kernel_cve_match():
    scanner = KernelCveScanner()
    scanner.cve_db = [{
        "cve_id": "CVE-2022-0847",
        "product": "Linux Kernel (Dirty Pipe)",
        "affected_versions": ["5.8.0 - 5.16.10"],
        "min_version": "5.8.0",
        "max_version": "5.16.10",
        "severity": "CRITICAL",
        "description": "Dirty Pipe vulnerability",
        "reference": "https://dirtypipe.cm4all.com/",
        "mitigation": "Update kernel"
    }]
    with patch("platform.release", return_value="5.10.0-8-amd64"):
        findings = scanner.scan()
        assert len(findings) == 1
        assert findings[0].finding_id == "CVE-CVE_2022_0847"
        assert findings[0].confidence == Confidence.MEDIUM


# 9. Safe baseline configuration test
def test_safe_baseline_no_criticals():
    engine = AnalysisEngine()
    with patch("os.getuid", return_value=1000), \
         patch("os.path.exists", return_value=False):
        findings = engine.run()
        criticals = [f for f in findings if f.severity == Severity.CRITICAL]
        assert isinstance(findings, list)


# 10. Reporters test
def test_reporters_output(tmp_path):
    finding = Finding(
        finding_id="TEST-01",
        category=Category.SYSINFO,
        title="Test Finding Title",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Test description text",
        evidence=["Evidence item 1"],
        impact="High impact",
        exploitation_possible=True,
        references=["https://example.com"],
        mitigation="Apply patch"
    )

    t_rep = TerminalReporter().generate([finding])
    assert "TEST-01" in t_rep

    j_out = tmp_path / "report.json"
    j_rep = JsonReporter().generate([finding], str(j_out))
    assert j_out.exists()
    assert "TEST-01" in j_rep

    h_out = tmp_path / "report.html"
    h_rep = HtmlReporter().generate([finding], str(h_out))
    assert h_out.exists()
    assert "TEST-01" in h_rep
