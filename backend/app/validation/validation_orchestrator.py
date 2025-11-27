"""
Validation Orchestrator

Manages all PoC validators and orchestrates vulnerability validation.
"""
import logging
from typing import List, Optional, Dict, Any
from dataclasses import asdict

from app.models import Vulnerability
from app.utils import PentestHTTPClient
from app.validation.base_validator import BaseValidator, ValidationResult, ValidationStatus
from app.validation.sql_validator import SQLInjectionValidator
from app.validation.xss_validator import XSSValidator
from app.validation.ssrf_validator import SSRFValidator
from app.validation.rce_validator import RCEValidator

logger = logging.getLogger(__name__)

class ValidationOrchestrator:
    """
    Orchestrates PoC validation across all validators

    Features:
    - Routes vulnerabilities to appropriate validators
    - Manages validation lifecycle
    - Aggregates validation results
    - Updates vulnerability confidence scores
    - Eliminates false positives
    """

    def __init__(self):
        """Initialize all validators"""
        self.validators: List[BaseValidator] = [
            SQLInjectionValidator(),
            XSSValidator(),
            SSRFValidator(),
            RCEValidator(),
        ]

        logger.info(f"✅ ValidationOrchestrator initialized with {len(self.validators)} validators")

    async def validate_vulnerability(
        self,
        vulnerability: Vulnerability,
        target_url: str,
        client: Optional[PentestHTTPClient] = None,
        **kwargs
    ) -> Optional[ValidationResult]:
        """
        Validate a single vulnerability

        Tries all applicable validators until one succeeds.

        Args:
            vulnerability: Vulnerability to validate
            target_url: Base target URL
            client: HTTP client (optional, will create if needed)
            **kwargs: Additional validation parameters

        Returns:
            ValidationResult if validation succeeded, None otherwise
        """
        logger.info(f"🔍 Validating: {vulnerability.title}")

        if client is None:
            client = PentestHTTPClient(base_url=target_url)

        # Try each validator
        for validator in self.validators:
            try:
                result = await validator.validate(
                    vulnerability=vulnerability,
                    target_url=target_url,
                    client=client,
                    **kwargs
                )

                if result:
                    logger.info(
                        f"✅ Validation complete: {result.status.value} "
                        f"(confidence: {result.confidence:.2f})"
                    )
                    return result

            except Exception as e:
                logger.error(f"❌ Validator {validator.__class__.__name__} failed: {e}")
                continue

        # No validator succeeded
        logger.warning(f"⚠️  Could not validate: {vulnerability.title}")
        return None

    async def validate_all(
        self,
        vulnerabilities: List[Vulnerability],
        target_url: str,
        client: Optional[PentestHTTPClient] = None,
        **kwargs
    ) -> Dict[str, ValidationResult]:
        """
        Validate all vulnerabilities

        Args:
            vulnerabilities: List of vulnerabilities to validate
            target_url: Base target URL
            client: HTTP client (optional)
            **kwargs: Additional validation parameters

        Returns:
            Dict mapping vulnerability ID to ValidationResult
        """
        logger.info(f"🚀 Starting validation for {len(vulnerabilities)} vulnerabilities")

        if client is None:
            client = PentestHTTPClient(base_url=target_url)

        results = {}

        for vuln in vulnerabilities:
            try:
                result = await self.validate_vulnerability(
                    vulnerability=vuln,
                    target_url=target_url,
                    client=client,
                    **kwargs
                )

                if result:
                    results[vuln.id] = result

            except Exception as e:
                logger.error(f"❌ Failed to validate {vuln.id}: {e}")
                continue

        # Log summary
        confirmed = sum(1 for r in results.values() if r.status == ValidationStatus.CONFIRMED)
        likely = sum(1 for r in results.values() if r.status == ValidationStatus.LIKELY)
        unconfirmed = sum(1 for r in results.values() if r.status == ValidationStatus.UNCONFIRMED)
        false_positives = sum(1 for r in results.values() if r.status == ValidationStatus.FALSE_POSITIVE)

        logger.info(
            f"✅ Validation complete: "
            f"{confirmed} confirmed, {likely} likely, "
            f"{unconfirmed} unconfirmed, {false_positives} false positives"
        )

        return results

    async def update_vulnerabilities_with_validation(
        self,
        vulnerabilities: List[Vulnerability],
        validation_results: Dict[str, ValidationResult]
    ) -> List[Vulnerability]:
        """
        Update vulnerability objects with validation results

        Args:
            vulnerabilities: Original vulnerabilities
            validation_results: Validation results by ID

        Returns:
            Updated vulnerabilities with validation data
        """
        updated = []

        for vuln in vulnerabilities:
            if vuln.id in validation_results:
                result = validation_results[vuln.id]

                # Update vulnerability with validation info
                vuln_dict = vuln.dict() if hasattr(vuln, 'dict') else asdict(vuln)

                # Add validation fields
                vuln_dict['validation_status'] = result.status.value
                vuln_dict['confidence_score'] = result.confidence
                vuln_dict['poc_evidence'] = result.evidence
                vuln_dict['validation_details'] = result.details
                vuln_dict['validated_at'] = result.validated_at.isoformat()

                # Recreate vulnerability with updated data
                # Note: Adjust this based on your Vulnerability class constructor
                updated_vuln = Vulnerability(**vuln_dict)
                updated.append(updated_vuln)
            else:
                # No validation result, keep original
                updated.append(vuln)

        return updated

    def get_statistics(self, validation_results: Dict[str, ValidationResult]) -> Dict[str, Any]:
        """
        Get validation statistics

        Args:
            validation_results: Validation results

        Returns:
            Statistics dictionary
        """
        if not validation_results:
            return {
                "total": 0,
                "confirmed": 0,
                "likely": 0,
                "unconfirmed": 0,
                "false_positives": 0,
                "average_confidence": 0.0
            }

        confirmed = sum(1 for r in validation_results.values() if r.status == ValidationStatus.CONFIRMED)
        likely = sum(1 for r in validation_results.values() if r.status == ValidationStatus.LIKELY)
        unconfirmed = sum(1 for r in validation_results.values() if r.status == ValidationStatus.UNCONFIRMED)
        false_positives = sum(1 for r in validation_results.values() if r.status == ValidationStatus.FALSE_POSITIVE)

        # Calculate average confidence
        total_confidence = sum(r.confidence for r in validation_results.values())
        avg_confidence = total_confidence / len(validation_results) if validation_results else 0.0

        return {
            "total": len(validation_results),
            "confirmed": confirmed,
            "likely": likely,
            "unconfirmed": unconfirmed,
            "false_positives": false_positives,
            "average_confidence": round(avg_confidence, 2),
            "confirmation_rate": round(confirmed / len(validation_results) * 100, 1) if validation_results else 0.0
        }

    def filter_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        validation_results: Dict[str, ValidationResult],
        min_confidence: float = 0.5,
        exclude_false_positives: bool = True
    ) -> List[Vulnerability]:
        """
        Filter vulnerabilities based on validation results

        Args:
            vulnerabilities: All vulnerabilities
            validation_results: Validation results
            min_confidence: Minimum confidence threshold
            exclude_false_positives: Exclude false positives

        Returns:
            Filtered vulnerability list
        """
        filtered = []

        for vuln in vulnerabilities:
            # If no validation result, keep it (not yet validated)
            if vuln.id not in validation_results:
                filtered.append(vuln)
                continue

            result = validation_results[vuln.id]

            # Exclude false positives
            if exclude_false_positives and result.status == ValidationStatus.FALSE_POSITIVE:
                logger.debug(f"Filtering out false positive: {vuln.title}")
                continue

            # Check confidence threshold
            if result.confidence < min_confidence:
                logger.debug(f"Filtering out low confidence ({result.confidence}): {vuln.title}")
                continue

            filtered.append(vuln)

        logger.info(f"Filtered {len(vulnerabilities)} → {len(filtered)} vulnerabilities")
        return filtered


# Singleton instance
_validation_orchestrator: Optional[ValidationOrchestrator] = None

def get_validation_orchestrator() -> ValidationOrchestrator:
    """Get or create validation orchestrator singleton"""
    global _validation_orchestrator
    if _validation_orchestrator is None:
        _validation_orchestrator = ValidationOrchestrator()
    return _validation_orchestrator
