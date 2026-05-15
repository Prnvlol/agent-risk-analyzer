"""Detector registry — all active detectors are imported and listed here."""

from src.detectors.code_execution import CodeExecutionDetector
from src.detectors.credentials import CredentialsDetector
from src.detectors.framework_specific import FrameworkSpecificDetector
from src.detectors.logging_detector import LoggingDetector
from src.detectors.mcp_config import MCPConfigDetector
from src.detectors.multi_agent import MultiAgentDetector
from src.detectors.prompt_injection import PromptInjectionDetector
from src.detectors.rate_limiting import RateLimitingDetector
from src.detectors.tool_permissions import ToolPermissionsDetector

ALL_DETECTORS = [
    CredentialsDetector(),
    CodeExecutionDetector(),
    PromptInjectionDetector(),
    ToolPermissionsDetector(),
    MCPConfigDetector(),
    MultiAgentDetector(),
    FrameworkSpecificDetector(),
    LoggingDetector(),
    RateLimitingDetector(),
]

__all__ = ["ALL_DETECTORS"]
