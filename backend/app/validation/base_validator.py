"""
PoC Validation Framework

Automatically validates vulnerabilities with real proof-of-concept exploits.
Eliminates false positives by confirming vulnerabilities are actually exploitable.
"""
import logging
from typing import Optional, Dict, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

class ValidationStatus(str, Enum):
    """Validation status"""
    CONFIRMED = "confirmed"          # Vulnerability confirmed with PoC
    LIKELY = "likely"                # Likely vulnerable but not confirmed
    UNCONFIRMED = "unconfirmed"      # Could not confirm
    FALSE_POSITIVE = "false_positive" # Confirmed false positive

@dataclass
class ValidationResult:
    """Result of PoC validation"""
    status: ValidationStatus
    confidence: float  # 0.0 to 1.0
    evidence: str      # Proof of exploitation
    validated_at: datetime
    validator_name: str
    details: Dict[str, Any]

    def to_dict(self):
        return {
            "status": self.status.value,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "validated_at": self.validated_at.isoformat(),
            "validator_name": self.validator_name,
            "details": self.details
        }

class BaseValidator:
    """
    Base class for PoC validators

    Each validator implements safe exploitation to confirm vulnerabilities.
    """

    def __init__(self):
        self.name = self.__class__.__name__

    async def validate(
        self,
        vulnerability: Any,
        target_url: str,
        **kwargs
    ) -> Optional[ValidationResult]:
        """
        Validate a vulnerability with PoC

        Args:
            vulnerability: Vulnerability object
            target_url: Target URL
            **kwargs: Additional parameters

        Returns:
            ValidationResult or None if not applicable
        """
        raise NotImplementedError("Subclasses must implement validate()")

    def _create_result(
        self,
        status: ValidationStatus,
        confidence: float,
        evidence: str,
        details: Dict[str, Any] = None
    ) -> ValidationResult:
        """Helper to create validation result"""
        return ValidationResult(
            status=status,
            confidence=confidence,
            evidence=evidence,
            validated_at=datetime.utcnow(),
            validator_name=self.name,
            details=details or {}
        )

    def _is_applicable(self, vulnerability: Any) -> bool:
        """Check if this validator applies to the vulnerability"""
        return True  # Override in subclasses
