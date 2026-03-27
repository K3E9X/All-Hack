"""
Memory and Learning System - Persistent pattern storage
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, func


class MemorySystem:
    """
    Persistent memory system for agent learning

    Stores and retrieves:
    - Successful payloads and techniques
    - Exploitation chains that worked
    - Target-specific patterns
    """

    def __init__(self, db_session: Session = None):
        self.db = db_session
        self._cache: Dict[str, Any] = {}

    def set_session(self, db_session: Session):
        """Set database session"""
        self.db = db_session

    async def record_success(
        self,
        pattern_type: str,
        category: str,
        context: Dict[str, Any],
        payload: str = None,
        technique: str = None,
        metadata: Dict[str, Any] = None
    ):
        """
        Record a successful pattern

        Args:
            pattern_type: Type of pattern (payload, technique, chain, bypass)
            category: Vulnerability category (sqli, xss, rce, etc.)
            context: When this works (tech stack, WAF, etc.)
            payload: The actual payload that worked
            technique: The technique name
            metadata: Additional information
        """
        if not self.db:
            # Cache in memory if no DB
            key = f"{pattern_type}:{category}"
            if key not in self._cache:
                self._cache[key] = []
            self._cache[key].append({
                "context": context,
                "payload": payload,
                "technique": technique,
                "success_count": 1
            })
            return

        try:
            from app.database.models import AgentMemory

            # Check if pattern exists
            existing = self.db.query(AgentMemory).filter(
                AgentMemory.pattern_type == pattern_type,
                AgentMemory.category == category,
                AgentMemory.payload == payload
            ).first()

            if existing:
                existing.record_usage(succeeded=True)
            else:
                memory = AgentMemory(
                    pattern_type=pattern_type,
                    category=category,
                    context=context,
                    payload=payload,
                    technique=technique,
                    times_used=1,
                    times_succeeded=1,
                    success_rate=1.0,
                    extra_data=metadata or {}
                )
                self.db.add(memory)

            self.db.commit()

        except Exception as e:
            self.db.rollback()
            print(f"[Memory] Error recording success: {e}")

    async def record_failure(
        self,
        pattern_type: str,
        category: str,
        context: Dict[str, Any],
        payload: str = None
    ):
        """Record a failed attempt"""
        if not self.db:
            return

        try:
            from app.database.models import AgentMemory

            existing = self.db.query(AgentMemory).filter(
                AgentMemory.pattern_type == pattern_type,
                AgentMemory.category == category,
                AgentMemory.payload == payload
            ).first()

            if existing:
                existing.record_usage(succeeded=False)
                self.db.commit()

        except Exception as e:
            self.db.rollback()

    async def get_best_payloads(
        self,
        category: str,
        context: Dict[str, Any] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get most successful payloads for a category

        Args:
            category: Vulnerability category
            context: Optional context for filtering
            limit: Maximum results

        Returns:
            List of payloads sorted by success rate
        """
        if not self.db:
            # Return from cache
            key = f"payload:{category}"
            cached = self._cache.get(key, [])
            return sorted(cached, key=lambda x: x.get("success_count", 0), reverse=True)[:limit]

        try:
            from app.database.models import AgentMemory

            query = self.db.query(AgentMemory).filter(
                AgentMemory.pattern_type == "payload",
                AgentMemory.category == category,
                AgentMemory.times_used >= 1
            ).order_by(
                desc(AgentMemory.success_rate),
                desc(AgentMemory.times_succeeded)
            ).limit(limit)

            results = []
            for mem in query.all():
                results.append({
                    "payload": mem.payload,
                    "technique": mem.technique,
                    "success_rate": mem.success_rate,
                    "times_used": mem.times_used,
                    "context": mem.context
                })

            return results

        except Exception as e:
            print(f"[Memory] Error getting payloads: {e}")
            return []

    async def get_successful_chains(
        self,
        chain_type: str = None,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get successful exploitation chains"""
        if not self.db:
            return []

        try:
            from app.database.models import ExploitChain

            query = self.db.query(ExploitChain)

            if chain_type:
                query = query.filter(ExploitChain.chain_type == chain_type)

            query = query.filter(
                ExploitChain.times_succeeded >= 1
            ).order_by(
                desc(ExploitChain.success_rate)
            ).limit(limit)

            results = []
            for chain in query.all():
                results.append({
                    "chain_type": chain.chain_type,
                    "name": chain.name,
                    "steps": chain.steps,
                    "success_rate": chain.success_rate,
                    "target_pattern": chain.target_pattern
                })

            return results

        except Exception as e:
            print(f"[Memory] Error getting chains: {e}")
            return []

    async def record_chain_success(
        self,
        chain_type: str,
        steps: List[Dict[str, Any]],
        target_pattern: Dict[str, Any] = None,
        name: str = None
    ):
        """Record a successful exploitation chain"""
        if not self.db:
            return

        try:
            from app.database.models import ExploitChain

            # Check if chain exists
            existing = self.db.query(ExploitChain).filter(
                ExploitChain.chain_type == chain_type,
                ExploitChain.steps == steps
            ).first()

            if existing:
                existing.times_attempted += 1
                existing.times_succeeded += 1
                existing.success_rate = existing.times_succeeded / existing.times_attempted
                existing.last_used = datetime.utcnow()
            else:
                chain = ExploitChain(
                    chain_type=chain_type,
                    name=name or chain_type,
                    steps=steps,
                    target_pattern=target_pattern or {},
                    times_attempted=1,
                    times_succeeded=1,
                    success_rate=1.0
                )
                self.db.add(chain)

            self.db.commit()

        except Exception as e:
            self.db.rollback()
            print(f"[Memory] Error recording chain: {e}")

    async def get_relevant_context(
        self,
        target: str,
        request: str
    ) -> Dict[str, Any]:
        """
        Get relevant context from memory for planning

        Returns patterns and techniques that might be useful
        based on the target and request.
        """
        context = {
            "known_patterns": [],
            "suggested_payloads": [],
            "successful_chains": []
        }

        if not self.db:
            return context

        try:
            from app.database.models import AgentMemory, ExploitChain

            # Get high success rate patterns
            top_patterns = self.db.query(AgentMemory).filter(
                AgentMemory.success_rate >= 0.5,
                AgentMemory.times_used >= 2
            ).order_by(
                desc(AgentMemory.success_rate)
            ).limit(10).all()

            for pattern in top_patterns:
                context["known_patterns"].append({
                    "category": pattern.category,
                    "technique": pattern.technique,
                    "success_rate": pattern.success_rate
                })

            # Detect request intent and get relevant payloads
            request_lower = request.lower()
            categories = []
            if "sql" in request_lower:
                categories.append("sqli")
            if "xss" in request_lower:
                categories.append("xss")
            if "rce" in request_lower or "command" in request_lower:
                categories.append("rce")

            for cat in categories:
                payloads = await self.get_best_payloads(cat, limit=3)
                context["suggested_payloads"].extend(payloads)

            # Get successful chains
            chains = await self.get_successful_chains(limit=3)
            context["successful_chains"] = chains

        except Exception as e:
            print(f"[Memory] Error getting context: {e}")

        return context

    async def get_stats(self) -> Dict[str, Any]:
        """Get memory system statistics"""
        if not self.db:
            return {
                "patterns_cached": sum(len(v) for v in self._cache.values()),
                "database_connected": False
            }

        try:
            from app.database.models import AgentMemory, ExploitChain

            pattern_count = self.db.query(func.count(AgentMemory.id)).scalar()
            chain_count = self.db.query(func.count(ExploitChain.id)).scalar()
            avg_success = self.db.query(func.avg(AgentMemory.success_rate)).scalar()

            return {
                "total_patterns": pattern_count,
                "total_chains": chain_count,
                "average_success_rate": round(avg_success or 0, 2),
                "database_connected": True
            }

        except Exception as e:
            return {"error": str(e), "database_connected": False}
