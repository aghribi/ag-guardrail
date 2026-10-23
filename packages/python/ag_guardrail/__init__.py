"""guardrail — runtime safety proxy for LLM applications."""

from importlib.metadata import version as _version

from .models   import CheckResult, ScanResult, AuditEntry, Severity
from .scanner  import Scanner
from .audit    import AuditLog
from .policy   import Policy, PolicyConfig, DEFAULT_POLICY
from .proxy    import SafeOpenAI, GuardrailError
from .hosted   import HostedGuardrail, QuotaExceededError
from .detectors import (
    Detector,
    PromptInjectionDetector,
    JailbreakDetector,
    PIIOutputDetector,
    TopicFilter,
    HarmfulContentDetector,
    BUILTIN_TOPICS,
)

__version__ = _version("ag-guardrail")

__all__ = [
    "CheckResult", "ScanResult", "AuditEntry", "Severity",
    "Scanner", "AuditLog",
    "Policy", "PolicyConfig", "DEFAULT_POLICY",
    "SafeOpenAI", "GuardrailError", "HostedGuardrail", "QuotaExceededError",
    "Detector", "PromptInjectionDetector", "JailbreakDetector",
    "PIIOutputDetector", "TopicFilter", "HarmfulContentDetector", "BUILTIN_TOPICS",
]
