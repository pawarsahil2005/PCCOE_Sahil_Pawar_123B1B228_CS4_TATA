"""Re-export local_llm_client for backwards compatibility."""

from local_llm_client import (
    AIProvider,
    AIResult,
    GeminiProvider,
    LocalLLMProvider,
    RuleBasedOnlyProvider,
    get_ai_provider,
)

__all__ = [
    "AIProvider",
    "AIResult",
    "LocalLLMProvider",
    "GeminiProvider",
    "RuleBasedOnlyProvider",
    "get_ai_provider",
]
