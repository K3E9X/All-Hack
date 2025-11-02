"""
Scan persistence - Save and resume scans
"""
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from app.models import ScanResult

logger = logging.getLogger(__name__)

class ScanStorage:
    """
    Persistent storage for scan results to prevent data loss
    """

    def __init__(self, storage_dir: str = "/tmp/pentest_scans"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def save_scan(self, scan_result: ScanResult) -> bool:
        """
        Save scan result to disk

        Returns:
            True if saved successfully
        """
        try:
            filename = f"scan_{scan_result.scan_id}.json"
            filepath = self.storage_dir / filename

            # Convert to dict
            data = scan_result.model_dump(mode='json')

            # Save to file
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)

            logger.info(f"💾 Saved scan {scan_result.scan_id} to {filepath}")
            return True

        except Exception as e:
            logger.error(f"Failed to save scan {scan_result.scan_id}: {e}")
            return False

    def load_scan(self, scan_id: str) -> Optional[ScanResult]:
        """
        Load scan result from disk

        Returns:
            ScanResult or None if not found
        """
        try:
            filename = f"scan_{scan_id}.json"
            filepath = self.storage_dir / filename

            if not filepath.exists():
                logger.warning(f"Scan file not found: {filepath}")
                return None

            with open(filepath, 'r') as f:
                data = json.load(f)

            scan_result = ScanResult(**data)
            logger.info(f"💾 Loaded scan {scan_id} from disk")
            return scan_result

        except Exception as e:
            logger.error(f"Failed to load scan {scan_id}: {e}")
            return None

    def auto_save_scan(self, scan_result: ScanResult):
        """Auto-save scan periodically during execution"""
        try:
            self.save_scan(scan_result)
        except Exception as e:
            logger.error(f"Auto-save failed for {scan_result.scan_id}: {e}")

    def get_all_scans(self) -> list:
        """Get list of all stored scans"""
        try:
            scan_files = list(self.storage_dir.glob("scan_*.json"))
            scans = []

            for filepath in scan_files:
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        scans.append({
                            'scan_id': data.get('scan_id'),
                            'target_url': data.get('target_url'),
                            'status': data.get('status'),
                            'start_time': data.get('start_time'),
                            'end_time': data.get('end_time')
                        })
                except:
                    continue

            return scans

        except Exception as e:
            logger.error(f"Failed to get all scans: {e}")
            return []

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a stored scan"""
        try:
            filename = f"scan_{scan_id}.json"
            filepath = self.storage_dir / filename

            if filepath.exists():
                filepath.unlink()
                logger.info(f"Deleted scan {scan_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to delete scan {scan_id}: {e}")
            return False

    def generate_markdown_report(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Generate a Markdown report for the provided scan result."""

        report_lines = [
            f"# Pentest Report for {scan_result.target_url}",
            "",
            f"- **Scan ID:** {scan_result.scan_id}",
            f"- **Mode:** {scan_result.mode.value}",
            f"- **Start:** {scan_result.start_time}",
            f"- **End:** {scan_result.end_time or 'running'}",
            f"- **Total Requests:** {scan_result.total_requests}",
            "",
            "## Vulnerabilities",
        ]

        if scan_result.vulnerabilities:
            for vuln in scan_result.vulnerabilities:
                report_lines.extend([
                    f"### {vuln.title} ({vuln.severity.value.upper()})",
                    vuln.description,
                    "",
                    f"- Affected URL: `{vuln.affected_url}`",
                    f"- Remediation: {vuln.remediation}",
                    "",
                ])
        else:
            report_lines.append("No vulnerabilities detected.")

        if scan_result.osint_findings:
            report_lines.extend(["## OSINT Findings", ""])
            for finding in scan_result.osint_findings:
                report_lines.append(f"- **{finding.get('type')}**: {json.dumps(finding, default=str)}")

        if scan_result.attack_chains:
            report_lines.extend(["", "## Planned Attack Chains", ""])
            for chain in scan_result.attack_chains:
                report_lines.append(f"### {chain.name}")
                report_lines.append(chain.description)
                report_lines.append("")
                report_lines.append("Steps:")
                for step in chain.steps:
                    report_lines.append(f"- {step}")
                report_lines.append("")

        report_content = "\n".join(report_lines)
        report_path = self.storage_dir / f"report_{scan_result.scan_id}.md"
        report_path.write_text(report_content, encoding="utf-8")

        return {"path": str(report_path), "content": report_content}

    def compare_scans(self, scan_a: ScanResult, scan_b: ScanResult) -> Dict[str, Any]:
        """Compare two scans and return differences."""

        def summarize(scan: ScanResult) -> Dict[str, Any]:
            return {
                "target": scan.target_url,
                "vulnerabilities": len(scan.vulnerabilities),
                "misconfigurations": len(scan.misconfigurations),
                "critical": sum(1 for v in scan.vulnerabilities if v.severity.value == "critical"),
                "high": sum(1 for v in scan.vulnerabilities if v.severity.value == "high"),
            }

        summary_a = summarize(scan_a)
        summary_b = summarize(scan_b)

        ids_a = {v.id for v in scan_a.vulnerabilities}
        ids_b = {v.id for v in scan_b.vulnerabilities}

        diff = {
            "summary_a": summary_a,
            "summary_b": summary_b,
            "regressions": [
                v.title for v in scan_b.vulnerabilities if v.id not in ids_a
            ],
            "improvements": [
                v.title for v in scan_a.vulnerabilities if v.id not in ids_b
            ],
        }

        return diff
