"""
Scan Memory - Learn from Previous Scans

Stores and retrieves scan results for learning.
"""
import logging
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class ScanMemoryEntry:
    """Memory entry for a scan"""
    scan_id: str
    target_url: str
    target_domain: str
    technologies: List[str]
    vulnerabilities_found: int
    vulnerability_types: List[str]
    successful_payloads: List[Dict[str, Any]]
    failed_payloads: List[Dict[str, Any]]
    scan_duration: float
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class ScanMemory:
    """
    Scan Memory System

    Stores historical scan data for learning:
    - Successful payloads for similar targets
    - Technology-specific vulnerabilities
    - Effective enumeration techniques
    - WAF bypass methods

    Future: Will use pgvector for semantic search
    """

    def __init__(self, memory_path: str = "data/memory"):
        """
        Initialize scan memory

        Args:
            memory_path: Path to store memory files
        """
        self.memory_path = Path(memory_path)
        self.memory_path.mkdir(parents=True, exist_ok=True)

        self.memory_file = self.memory_path / "scan_memory.json"
        self.memories: List[ScanMemoryEntry] = []

        self._load_memory()

        logger.info(f"📚 Scan Memory initialized with {len(self.memories)} entries")

    def _load_memory(self):
        """Load memories from disk"""
        if self.memory_file.exists():
            try:
                with open(self.memory_file, 'r') as f:
                    data = json.load(f)
                    self.memories = [
                        ScanMemoryEntry(**entry) for entry in data
                    ]
                logger.info(f"✅ Loaded {len(self.memories)} memories from disk")
            except Exception as e:
                logger.error(f"❌ Failed to load memory: {e}")
                self.memories = []
        else:
            self.memories = []

    def _save_memory(self):
        """Save memories to disk"""
        try:
            with open(self.memory_file, 'w') as f:
                json.dump(
                    [m.to_dict() for m in self.memories],
                    f,
                    indent=2
                )
            logger.info(f"💾 Saved {len(self.memories)} memories to disk")
        except Exception as e:
            logger.error(f"❌ Failed to save memory: {e}")

    def store_scan(
        self,
        scan_id: str,
        target_url: str,
        scan_result: Dict[str, Any]
    ):
        """
        Store scan result in memory

        Args:
            scan_id: Scan identifier
            target_url: Target URL
            scan_result: Complete scan result
        """
        from urllib.parse import urlparse

        # Extract domain
        domain = urlparse(target_url).netloc

        # Extract technologies
        technologies = [
            t.get("name", "unknown")
            for t in scan_result.get("detected_technologies", [])
        ]

        # Extract vulnerability info
        vulnerabilities = scan_result.get("vulnerabilities", [])
        vuln_types = list(set([
            v.get("category", "unknown") for v in vulnerabilities
        ]))

        # Create memory entry
        entry = ScanMemoryEntry(
            scan_id=scan_id,
            target_url=target_url,
            target_domain=domain,
            technologies=technologies,
            vulnerabilities_found=len(vulnerabilities),
            vulnerability_types=vuln_types,
            successful_payloads=[],  # TODO: Extract from validation results
            failed_payloads=[],
            scan_duration=scan_result.get("scan_duration", 0),
            timestamp=datetime.now().isoformat()
        )

        self.memories.append(entry)
        self._save_memory()

        logger.info(f"📝 Stored memory for scan {scan_id}")

    def recall_similar_scans(
        self,
        target_url: str,
        technologies: List[str] = None,
        limit: int = 5
    ) -> List[ScanMemoryEntry]:
        """
        Recall similar scans

        Args:
            target_url: Current target URL
            technologies: Target technologies
            limit: Max number of results

        Returns:
            List of similar scan memories
        """
        from urllib.parse import urlparse

        domain = urlparse(target_url).netloc

        # Find similar scans
        similar = []

        for memory in self.memories:
            similarity_score = 0

            # Same domain = high similarity
            if memory.target_domain == domain:
                similarity_score += 100

            # Similar technologies = medium similarity
            if technologies:
                tech_overlap = len(set(memory.technologies) & set(technologies))
                similarity_score += tech_overlap * 10

            if similarity_score > 0:
                similar.append((similarity_score, memory))

        # Sort by similarity
        similar.sort(key=lambda x: x[0], reverse=True)

        # Return top results
        results = [m for _, m in similar[:limit]]

        logger.info(f"🔍 Found {len(results)} similar scans for {target_url}")

        return results

    def get_successful_payloads(
        self,
        vulnerability_type: str,
        technology: str = None
    ) -> List[Dict[str, Any]]:
        """
        Get successful payloads for a vulnerability type

        Args:
            vulnerability_type: Type of vulnerability
            technology: Target technology (optional)

        Returns:
            List of successful payloads
        """
        payloads = []

        for memory in self.memories:
            # Filter by vulnerability type
            if vulnerability_type not in memory.vulnerability_types:
                continue

            # Filter by technology if specified
            if technology and technology not in memory.technologies:
                continue

            payloads.extend(memory.successful_payloads)

        logger.info(f"💡 Found {len(payloads)} successful payloads for {vulnerability_type}")

        return payloads

    def get_statistics(self) -> Dict[str, Any]:
        """Get memory statistics"""
        total_scans = len(self.memories)

        if total_scans == 0:
            return {
                "total_scans": 0,
                "unique_domains": 0,
                "total_vulnerabilities": 0,
                "most_common_vulnerabilities": []
            }

        # Unique domains
        unique_domains = len(set(m.target_domain for m in self.memories))

        # Total vulnerabilities
        total_vulns = sum(m.vulnerabilities_found for m in self.memories)

        # Most common vulnerability types
        vuln_counts = {}
        for memory in self.memories:
            for vuln_type in memory.vulnerability_types:
                vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1

        most_common = sorted(
            vuln_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        return {
            "total_scans": total_scans,
            "unique_domains": unique_domains,
            "total_vulnerabilities": total_vulns,
            "most_common_vulnerabilities": [
                {"type": v, "count": c} for v, c in most_common
            ]
        }

    def clear_memory(self):
        """Clear all memories"""
        self.memories = []
        self._save_memory()
        logger.info("🗑️  Memory cleared")


# Singleton instance
_scan_memory: Optional[ScanMemory] = None

def get_scan_memory() -> ScanMemory:
    """Get or create scan memory singleton"""
    global _scan_memory
    if _scan_memory is None:
        _scan_memory = ScanMemory()
    return _scan_memory
