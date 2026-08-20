"""Base detector interface."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from pydantic import BaseModel


class DetectorResult(BaseModel):
    """Output contract for any detector module."""
    name: str
    score: float  # [0.0, 1.0]
    triggered: bool
    labels: List[str]
    matched_patterns: List[str]
    description: str
    metadata: Dict[str, Any] = {}


class BaseDetector(ABC):
    """Abstract Base Class for all PromptShield detectors."""

    @abstractmethod
    def detect(self, text: str, normalized_text: str, metadata: Dict[str, Any]) -> DetectorResult:
        """
        Analyze the input text and return a DetectorResult.
        :param text: Original raw text
        :param normalized_text: Sanitized text after unicode and zero-width normalization
        :param metadata: Context or preprocessing metadata
        """
        pass
