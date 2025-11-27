"""
Vector Memory - Semantic Search with Embeddings

Future: Will use pgvector for production-grade semantic search
Current: Simple implementation for Phase 2
"""
import logging
from typing import Dict, Any, List, Optional
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class VectorMemory:
    """
    Vector Memory for Semantic Search

    Phase 2: Simple JSON-based storage
    Phase 3: Upgrade to pgvector with PostgreSQL

    Features:
    - Store scan results with embeddings
    - Semantic similarity search
    - Learn from historical data
    - Recommend attack vectors based on context
    """

    def __init__(self, storage_path: str = "data/vectors"):
        """
        Initialize vector memory

        Args:
            storage_path: Path to store vector data
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.vectors_file = self.storage_path / "vectors.json"
        self.vectors: List[Dict[str, Any]] = []

        self._load_vectors()

        logger.info(f"🧠 Vector Memory initialized with {len(self.vectors)} vectors")

    def _load_vectors(self):
        """Load vectors from disk"""
        if self.vectors_file.exists():
            try:
                with open(self.vectors_file, 'r') as f:
                    self.vectors = json.load(f)
                logger.info(f"✅ Loaded {len(self.vectors)} vectors from disk")
            except Exception as e:
                logger.error(f"❌ Failed to load vectors: {e}")
                self.vectors = []
        else:
            self.vectors = []

    def _save_vectors(self):
        """Save vectors to disk"""
        try:
            with open(self.vectors_file, 'w') as f:
                json.dump(self.vectors, f, indent=2)
            logger.info(f"💾 Saved {len(self.vectors)} vectors to disk")
        except Exception as e:
            logger.error(f"❌ Failed to save vectors: {e}")

    def store_vector(
        self,
        id: str,
        text: str,
        metadata: Dict[str, Any],
        vector: List[float] = None
    ):
        """
        Store a vector with metadata

        Args:
            id: Unique identifier
            text: Text content
            metadata: Associated metadata
            vector: Embedding vector (optional, will generate if None)

        Note: In Phase 3, we'll use OpenAI/Ollama embeddings
        """
        entry = {
            "id": id,
            "text": text,
            "metadata": metadata,
            "vector": vector or []  # Placeholder for actual embeddings
        }

        self.vectors.append(entry)
        self._save_vectors()

        logger.info(f"📝 Stored vector for {id}")

    def search(
        self,
        query: str,
        limit: int = 5,
        filter_metadata: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar vectors

        Args:
            query: Search query
            limit: Max results
            filter_metadata: Filter by metadata

        Returns:
            List of similar entries

        Note: In Phase 3, we'll use cosine similarity with embeddings
        """
        results = []

        # Simple keyword matching for Phase 2
        # In Phase 3: Use vector similarity
        query_lower = query.lower()

        for entry in self.vectors:
            # Check metadata filters
            if filter_metadata:
                matches_filter = all(
                    entry["metadata"].get(k) == v
                    for k, v in filter_metadata.items()
                )
                if not matches_filter:
                    continue

            # Simple text matching
            if query_lower in entry["text"].lower():
                results.append(entry)

        logger.info(f"🔍 Found {len(results)} results for query: {query}")

        return results[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get vector memory statistics"""
        return {
            "total_vectors": len(self.vectors),
            "storage_path": str(self.storage_path),
            "implementation": "JSON (Phase 2)",
            "future": "pgvector with PostgreSQL (Phase 3)"
        }


# Singleton instance
_vector_memory: Optional[VectorMemory] = None

def get_vector_memory() -> VectorMemory:
    """Get or create vector memory singleton"""
    global _vector_memory
    if _vector_memory is None:
        _vector_memory = VectorMemory()
    return _vector_memory
