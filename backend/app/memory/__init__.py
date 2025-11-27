"""
Long-Term Memory System

Enables agents to learn from previous scans using vector embeddings.
"""

from app.memory.vector_memory import VectorMemory, get_vector_memory
from app.memory.scan_memory import ScanMemory, ScanMemoryEntry

__all__ = [
    'VectorMemory',
    'get_vector_memory',
    'ScanMemory',
    'ScanMemoryEntry',
]
