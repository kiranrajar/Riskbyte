"""RiskByte Self-Hosted AI Analyst & Investigation Engine."""
from .llm import SelfHostedLLMClient, EgressSecurityViolation
from .tools import ToolExecutor, TOOL_REGISTRY
from .analyst import AIAnalystService

# Legacy / Prototype compatibility exports for unit test suite
from ..legacy_agent import (
    Intel, Triage, make_llm, parse_llm, SYSTEM, Redactor,
    OllamaClient, OpenAIClient, GeminiClient, VERDICTS, BASE, TOKEN
)
