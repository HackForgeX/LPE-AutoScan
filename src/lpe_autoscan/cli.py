"""
Command Line Interface (CLI) for LPE-AutoScan.
"""

import argparse
import sys
import json
from typing import List, Optional
from lpe_autoscan import __version__
from lpe_autoscan.logger import setup_logger
from lpe_autoscan.models import Severity, Finding


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lpe-autoscan",
        description="LPE-AutoScan: Linux Privilege Escalation Detection & Assessment Toolkit (Detection Only)",
    )
    parser.add_argument(
        "--version", "-V", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # scan sub-command
    scan_parser = subparsers.add_parser("scan", help="Run privilege escalation detection scan")
    scan_parser.add_argument(
        "--module",
        "-m",
        type=str,
        help="Specify specific module to scan (sysinfo, users, suid, permissions, sudo, cron, systemd, capabilities, ssh, docker, kernel)",
    )
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["terminal", "json", "html"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Save report output to specified file path",
    )
    scan_parser.add_argument(
        "--severity",
        "-s",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Filter findings by minimum severity",
    )
    scan_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress non-error terminal output",
    )
    scan_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose debug output",
    )

    # report sub-command
    report_parser = subparsers.add_parser("report", help="Generate report from previous scan results")
    report_parser.add_argument(
        "--input",
        "-i",
        required=True,
        type=str,
        help="Input JSON scan results file",
    )
    report_parser.add_argument(
        "--format",
        "-f",
        choices=["terminal", "json", "html"],
        default="html",
        help="Output report format (default: html)",
    )
    report_parser.add_argument(
        "--output",
        "-o",
        required=True,
        type=str,
        help="Output report file path",
    )

    # version sub-command
    version_parser = subparsers.add_parser("version", help="Show version information")

    return parser


def main(args: Optional[List[str]] = None) -> int:
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 0

    if parsed_args.command == "version":
        print(f"LPE-AutoScan v{__version__} (Defensive Linux Privilege Escalation Detection Toolkit)")
        return 0

    if parsed_args.command == "scan":
        logger = setup_logger(
            verbose=getattr(parsed_args, "verbose", False),
            quiet=getattr(parsed_args, "quiet", False),
        )
        logger.info(f"Starting LPE-AutoScan v{__version__}")

        from lpe_autoscan.engine import AnalysisEngine
        from lpe_autoscan.reporters.terminal import TerminalReporter
        from lpe_autoscan.reporters.json_reporter import JsonReporter
        from lpe_autoscan.reporters.html_reporter import HtmlReporter

        engine = AnalysisEngine(
            selected_module=getattr(parsed_args, "module", None),
            min_severity=getattr(parsed_args, "severity", None)
        )
        findings = engine.run()

        fmt = getattr(parsed_args, "format", "terminal")
        out_path = getattr(parsed_args, "output", None)

        if fmt == "terminal":
            reporter = TerminalReporter()
            output_text = reporter.generate(findings, out_path)
            if not parsed_args.quiet:
                print(output_text)
        elif fmt == "json":
            reporter = JsonReporter()
            output_text = reporter.generate(findings, out_path)
            if not parsed_args.quiet:
                print(output_text)
        elif fmt == "html":
            reporter = HtmlReporter()
            output_text = reporter.generate(findings, out_path)
            if out_path:
                logger.info(f"HTML report successfully written to {out_path}")
            elif not parsed_args.quiet:
                print(output_text)

        return 0

    if parsed_args.command == "report":
        from lpe_autoscan.reporters.terminal import TerminalReporter
        from lpe_autoscan.reporters.json_reporter import JsonReporter
        from lpe_autoscan.reporters.html_reporter import HtmlReporter
        from lpe_autoscan.models import Finding, Severity, Confidence, Category

        with open(parsed_args.input, "r") as f:
            data = json.load(f)

        raw_findings = data.get("findings", [])
        findings = []
        for rf in raw_findings:
            findings.append(
                Finding(
                    finding_id=rf["finding_id"],
                    category=Category(rf["category"]),
                    title=rf["title"],
                    severity=Severity(rf["severity"]),
                    confidence=Confidence(rf["confidence"]),
                    description=rf["description"],
                    evidence=rf["evidence"],
                    impact=rf["impact"],
                    exploitation_possible=rf.get("exploitation_possible", False),
                    references=rf.get("references", []),
                    mitigation=rf["mitigation"],
                    detected_at=rf.get("detected_at", "")
                )
            )

        fmt = getattr(parsed_args, "format", "html")
        if fmt == "html":
            HtmlReporter().generate(findings, parsed_args.output)
        elif fmt == "json":
            JsonReporter().generate(findings, parsed_args.output)
        elif fmt == "terminal":
            TerminalReporter().generate(findings, parsed_args.output)

        print(f"Report generated successfully: {parsed_args.output}")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
