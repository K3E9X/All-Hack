"""
Services package
"""

from .screenshot import (
    ScreenshotService,
    get_screenshot_service,
    capture_finding_screenshot
)

from .external_apis import (
    ExternalAPIs,
    get_external_apis,
    EnrichmentResult
)

from .llm_service import (
    LLMService,
    get_llm_service,
    analyze_with_llm
)

from .validation import (
    VulnerabilityValidator,
    ValidationResult,
    get_validator,
    validate_finding
)

from .ai_enhancements import (
    AIEnhancementService,
    AIEnhancementResult,
    get_ai_enhancements,
    init_ai_enhancements
)

__all__ = [
    # Screenshot
    "ScreenshotService",
    "get_screenshot_service",
    "capture_finding_screenshot",
    # External APIs
    "ExternalAPIs",
    "get_external_apis",
    "EnrichmentResult",
    # LLM
    "LLMService",
    "get_llm_service",
    "analyze_with_llm",
    # Validation
    "VulnerabilityValidator",
    "ValidationResult",
    "get_validator",
    "validate_finding",
    # AI Enhancements
    "AIEnhancementService",
    "AIEnhancementResult",
    "get_ai_enhancements",
    "init_ai_enhancements",
]
