"""
Scan persistence - Save and resume scans
"""
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional
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
