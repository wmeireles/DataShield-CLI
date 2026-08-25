"""Abstract base class for PII detectors."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Detection:
    """Represents a detected PII entity."""
    original: str
    token: str
    start: int
    end: int
    detector_name: str
    confidence: float = 1.0


class BaseDetector(ABC):
    """Abstract base class for all PII detectors.

    Each detector must implement:
    - name: Unique identifier for the detector
    - pattern: Compiled regex pattern for initial matching
    - validate(): Mathematical/logical validation of candidates
    - generate_token(): Create deterministic replacement token
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name identifier for this detector."""
        ...

    @property
    @abstractmethod
    def token_prefix(self) -> str:
        """Prefix used for replacement tokens (e.g., 'CPF', 'EMAIL')."""
        ...

    @abstractmethod
    def validate(self, candidate: str) -> bool:
        """Validate a candidate match using mathematical/logical rules.

        Args:
            candidate: The string candidate to validate

        Returns:
            True if candidate is valid PII, False otherwise
        """
        ...

    @abstractmethod
    def find_candidates(self, text: str) -> list[str]:
        """Find all candidate matches in text using regex pattern.

        Args:
            text: Input text to search

        Returns:
            List of candidate strings
        """
        ...

    def generate_token(self, index: int) -> str:
        """Generate a deterministic replacement token.

        Args:
            index: Sequential index for this detector type

        Returns:
            Formatted token string (e.g., '<CPF_1>')
        """
        return f"<{self.token_prefix}_{index}>"

    def detect(self, text: str) -> list[Detection]:
        """Detect all valid PII entities in text.

        Args:
            text: Input text to scan

        Returns:
            List of Detection objects with position info
        """
        detections: list[Detection] = []
        candidates = self.find_candidates(text)

        for candidate in candidates:
            if self.validate(candidate):
                start = text.find(candidate)
                if start >= 0:
                    end = start + len(candidate)
                    token = self.generate_token(len(detections) + 1)
                    detections.append(Detection(
                        original=candidate,
                        token=token,
                        start=start,
                        end=end,
                        detector_name=self.name,
                        confidence=1.0
                    ))

        # Sort by start position (reverse for safe replacement)
        detections.sort(key=lambda d: d.start, reverse=True)
        return detections
