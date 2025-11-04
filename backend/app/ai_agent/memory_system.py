"""
AI Agent Memory System
Persistent storage for learning patterns, successful exploits, and context

Features:
- Short-term memory (current scan session)
- Long-term memory (persistent across scans)
- Pattern learning from successful exploits
- Vulnerability correlation tracking
- Target-specific memory (remembers similar targets)
"""

import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class AgentMemory:
    """
    AI Agent Memory System with short-term and long-term storage

    Short-term: Current scan session
    Long-term: Persistent across scans, learns patterns
    """

    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize memory system

        Args:
            storage_path: Path to store persistent memory (default: ./data/agent_memory)
        """
        self.storage_path = Path(storage_path or "./data/agent_memory")
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Short-term memory (current scan)
        self.short_term: Dict[str, Any] = {
            "session_id": None,
            "target": None,
            "start_time": None,
            "decisions": [],
            "findings": [],
            "exploit_attempts": [],
            "successful_exploits": [],
            "failed_attempts": [],
        }

        # Long-term memory (persistent)
        self.long_term: Dict[str, Any] = self._load_long_term_memory()

        logger.info("🧠 AI Agent Memory System initialized")

    def start_session(self, session_id: str, target: str):
        """Start a new scan session"""
        self.short_term = {
            "session_id": session_id,
            "target": target,
            "start_time": datetime.utcnow().isoformat(),
            "decisions": [],
            "findings": [],
            "exploit_attempts": [],
            "successful_exploits": [],
            "failed_attempts": [],
        }
        logger.info(f"🧠 Memory: Started session {session_id} for target {target}")

    def remember_decision(self, decision: Dict[str, Any], context: Dict[str, Any]):
        """Remember an AI decision with its context"""
        memory_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "decision": decision,
            "context": context,
        }
        self.short_term["decisions"].append(memory_entry)

        # Also store in long-term for pattern learning
        self._add_to_pattern_learning("decisions", memory_entry)

    def remember_finding(self, vulnerability: Dict[str, Any]):
        """Remember a vulnerability found"""
        self.short_term["findings"].append({
            "timestamp": datetime.utcnow().isoformat(),
            "vulnerability": vulnerability,
        })

        # Update statistics in long-term memory
        vuln_type = vulnerability.get("category", "unknown")
        if vuln_type not in self.long_term["vulnerability_stats"]:
            self.long_term["vulnerability_stats"][vuln_type] = 0
        self.long_term["vulnerability_stats"][vuln_type] += 1

    def remember_exploit_attempt(self, test_type: str, target: str,
                                 payload: str, success: bool,
                                 result: Optional[Dict[str, Any]] = None):
        """Remember an exploit attempt (success or failure)"""
        attempt = {
            "timestamp": datetime.utcnow().isoformat(),
            "test_type": test_type,
            "target": target,
            "payload": payload,
            "success": success,
            "result": result,
        }

        if success:
            self.short_term["successful_exploits"].append(attempt)
            self._learn_successful_pattern(attempt)
        else:
            self.short_term["failed_attempts"].append(attempt)

        self.short_term["exploit_attempts"].append(attempt)

    def _learn_successful_pattern(self, successful_exploit: Dict[str, Any]):
        """Learn from successful exploit for future use"""
        test_type = successful_exploit["test_type"]

        if test_type not in self.long_term["successful_patterns"]:
            self.long_term["successful_patterns"][test_type] = []

        # Store pattern
        pattern = {
            "payload": successful_exploit["payload"],
            "target_pattern": self._extract_url_pattern(successful_exploit["target"]),
            "timestamp": successful_exploit["timestamp"],
            "result_indicators": successful_exploit.get("result", {}),
        }

        self.long_term["successful_patterns"][test_type].append(pattern)

        # Limit to last 100 patterns per type
        if len(self.long_term["successful_patterns"][test_type]) > 100:
            self.long_term["successful_patterns"][test_type] = \
                self.long_term["successful_patterns"][test_type][-100:]

        logger.info(f"🎓 Learned new pattern for {test_type}")

    def get_successful_patterns(self, test_type: str) -> List[Dict[str, Any]]:
        """Get previously successful patterns for a test type"""
        return self.long_term["successful_patterns"].get(test_type, [])

    def get_similar_target_insights(self, target: str) -> Dict[str, Any]:
        """Get insights from similar targets scanned before"""
        target_hash = self._hash_target(target)

        # Check if we've scanned similar targets
        similar_targets = []
        for past_target_hash, data in self.long_term["target_memory"].items():
            # Simple similarity: same domain or IP
            if self._targets_similar(target, data["target"]):
                similar_targets.append(data)

        if not similar_targets:
            return {"found_similar": False}

        # Aggregate insights
        common_vulns = {}
        for similar in similar_targets:
            for vuln_type, count in similar.get("vulnerability_types", {}).items():
                if vuln_type not in common_vulns:
                    common_vulns[vuln_type] = 0
                common_vulns[vuln_type] += count

        return {
            "found_similar": True,
            "similar_count": len(similar_targets),
            "common_vulnerabilities": common_vulns,
            "recommendations": self._generate_recommendations(common_vulns),
        }

    def _generate_recommendations(self, common_vulns: Dict[str, int]) -> List[str]:
        """Generate test recommendations based on patterns"""
        recommendations = []

        # Sort by frequency
        sorted_vulns = sorted(common_vulns.items(), key=lambda x: x[1], reverse=True)

        for vuln_type, count in sorted_vulns[:5]:
            if count >= 2:  # Found in at least 2 similar targets
                recommendations.append(
                    f"High probability of {vuln_type} (found in {count} similar targets)"
                )

        return recommendations

    def end_session(self):
        """End current session and save to long-term memory"""
        if not self.short_term["session_id"]:
            return

        # Calculate session statistics
        session_stats = {
            "session_id": self.short_term["session_id"],
            "target": self.short_term["target"],
            "start_time": self.short_term["start_time"],
            "end_time": datetime.utcnow().isoformat(),
            "total_findings": len(self.short_term["findings"]),
            "total_decisions": len(self.short_term["decisions"]),
            "total_exploits": len(self.short_term["exploit_attempts"]),
            "success_rate": self._calculate_success_rate(),
            "vulnerability_types": self._extract_vulnerability_types(),
        }

        # Store in target memory
        target_hash = self._hash_target(self.short_term["target"])
        self.long_term["target_memory"][target_hash] = session_stats

        # Update global statistics
        self.long_term["total_sessions"] += 1
        self.long_term["total_vulnerabilities"] += len(self.short_term["findings"])

        # Save to disk
        self._save_long_term_memory()

        logger.info(f"🧠 Memory: Session {self.short_term['session_id']} saved to long-term memory")
        logger.info(f"📊 Session stats: {session_stats['total_findings']} findings, "
                   f"{session_stats['success_rate']:.1%} success rate")

    def _calculate_success_rate(self) -> float:
        """Calculate exploit success rate"""
        total = len(self.short_term["exploit_attempts"])
        if total == 0:
            return 0.0
        successful = len(self.short_term["successful_exploits"])
        return successful / total

    def _extract_vulnerability_types(self) -> Dict[str, int]:
        """Extract vulnerability types from findings"""
        types = {}
        for finding in self.short_term["findings"]:
            vuln_type = finding["vulnerability"].get("category", "unknown")
            if vuln_type not in types:
                types[vuln_type] = 0
            types[vuln_type] += 1
        return types

    def get_learning_insights(self) -> Dict[str, Any]:
        """Get insights from long-term learning"""
        return {
            "total_sessions": self.long_term["total_sessions"],
            "total_vulnerabilities": self.long_term["total_vulnerabilities"],
            "most_common_vulnerabilities": sorted(
                self.long_term["vulnerability_stats"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "patterns_learned": sum(
                len(patterns) for patterns in self.long_term["successful_patterns"].values()
            ),
            "targets_scanned": len(self.long_term["target_memory"]),
        }

    def _load_long_term_memory(self) -> Dict[str, Any]:
        """Load long-term memory from disk"""
        memory_file = self.storage_path / "long_term_memory.json"

        if memory_file.exists():
            try:
                with open(memory_file, 'r') as f:
                    data = json.load(f)
                    logger.info(f"🧠 Loaded long-term memory: {data['total_sessions']} sessions, "
                               f"{data['total_vulnerabilities']} vulnerabilities")
                    return data
            except Exception as e:
                logger.error(f"Failed to load long-term memory: {e}")

        # Initialize new memory
        return {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat(),
            "total_sessions": 0,
            "total_vulnerabilities": 0,
            "vulnerability_stats": {},
            "successful_patterns": {},
            "target_memory": {},
            "pattern_learning": {
                "decisions": [],
                "exploits": [],
            }
        }

    def _save_long_term_memory(self):
        """Save long-term memory to disk"""
        memory_file = self.storage_path / "long_term_memory.json"

        try:
            with open(memory_file, 'w') as f:
                json.dump(self.long_term, f, indent=2)
            logger.debug("💾 Long-term memory saved to disk")
        except Exception as e:
            logger.error(f"Failed to save long-term memory: {e}")

    def _add_to_pattern_learning(self, category: str, data: Dict[str, Any]):
        """Add entry to pattern learning"""
        if category not in self.long_term["pattern_learning"]:
            self.long_term["pattern_learning"][category] = []

        self.long_term["pattern_learning"][category].append(data)

        # Limit to last 500 entries per category
        if len(self.long_term["pattern_learning"][category]) > 500:
            self.long_term["pattern_learning"][category] = \
                self.long_term["pattern_learning"][category][-500:]

    def _hash_target(self, target: str) -> str:
        """Hash target URL for storage"""
        return hashlib.md5(target.encode()).hexdigest()

    def _extract_url_pattern(self, url: str) -> str:
        """Extract pattern from URL (domain + path structure)"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        # Keep domain and first path segment
        path_parts = parsed.path.split('/')[:2]
        return f"{parsed.netloc}{''.join(path_parts)}"

    def _targets_similar(self, target1: str, target2: str) -> bool:
        """Check if two targets are similar"""
        from urllib.parse import urlparse
        parsed1 = urlparse(target1)
        parsed2 = urlparse(target2)

        # Same domain or same IP
        return parsed1.netloc == parsed2.netloc

    def export_session_report(self) -> Dict[str, Any]:
        """Export current session data for reporting"""
        return {
            "session_id": self.short_term["session_id"],
            "target": self.short_term["target"],
            "duration": self._calculate_duration(),
            "statistics": {
                "total_decisions": len(self.short_term["decisions"]),
                "total_findings": len(self.short_term["findings"]),
                "total_exploits": len(self.short_term["exploit_attempts"]),
                "successful_exploits": len(self.short_term["successful_exploits"]),
                "failed_attempts": len(self.short_term["failed_attempts"]),
                "success_rate": self._calculate_success_rate(),
            },
            "decisions": self.short_term["decisions"],
            "findings": self.short_term["findings"],
            "successful_exploits": self.short_term["successful_exploits"],
        }

    def _calculate_duration(self) -> str:
        """Calculate session duration"""
        if not self.short_term["start_time"]:
            return "N/A"

        start = datetime.fromisoformat(self.short_term["start_time"])
        duration = datetime.utcnow() - start

        hours, remainder = divmod(duration.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
