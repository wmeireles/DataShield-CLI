"""Sanitizer Engine orchestrating detection and replacement flow."""

from dataclasses import dataclass, field
from typing import Any

from datashield.core.vault import Vault
from datashield.detectors.base import BaseDetector, Detection
from datashield.detectors.br.common import get_br_detectors


@dataclass(slots=True)
class SanitizeResult:
    """Result of sanitization operation."""
    sanitized_text: str
    vault: Vault
    detections: list[Detection] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


class SanitizerEngine:
    """Orchestrates the PII detection and replacement pipeline."""

    def __init__(self, detectors: list[BaseDetector] | None = None):
        """Initialize engine with detectors.

        Args:
            detectors: List of detectors to use. Defaults to Brazilian detectors.
        """
        self.detectors = detectors or get_br_detectors()
        self.vault = Vault()

    def sanitize(self, text: str) -> SanitizeResult:
        """Sanitize text by replacing PII with tokens.

        Args:
            text: Input text to sanitize

        Returns:
            SanitizeResult with sanitized text and vault
        """
        if not text:
            return SanitizeResult(sanitized_text=text, vault=self.vault)

        all_detections = []
        for detector in self.detectors:
            detections = detector.detect(text)
            all_detections.extend(detections)

        # Sort by start position (forward) for deterministic token assignment
        all_detections.sort(key=lambda d: d.start)

        # Build token mapping based on first occurrence order
        token_map: dict[str, str] = {}  # original -> token

        for detection in all_detections:
            if detection.original in token_map:
                continue
            existing_token = self.vault.get_token_for(detection.original)
            if existing_token:
                token_map[detection.original] = existing_token
            else:
                # Count existing tokens for this detector type to determine next number
                count = sum(
                    1 for mapping in self.vault.get_all_mappings().values()
                    if mapping.detector_name == detection.detector_name
                ) + 1
                token = f"<{detection.detector_name.upper()}_{count}>"
                token_map[detection.original] = token
                self.vault.store(
                    token=token,
                    original=detection.original,
                    detector_name=detection.detector_name,
                    confidence=detection.confidence
                )

        # Now sort reverse for safe replacement
        all_detections.sort(key=lambda d: d.start, reverse=True)

        result_text = text
        stats: dict[str, int] = {}

        for detection in all_detections:
            token = token_map[detection.original]
            result_text = (
                result_text[:detection.start] + token + result_text[detection.end:]
            )

            stats[detection.detector_name] = stats.get(detection.detector_name, 0) + 1

        # Create updated detections with correct tokens for the result
        updated_detections = []
        for detection in all_detections:
            updated_detections.append(Detection(
                original=detection.original,
                token=token_map[detection.original],
                start=detection.start,
                end=detection.end,
                detector_name=detection.detector_name,
                confidence=detection.confidence
            ))

        return SanitizeResult(
            sanitized_text=result_text,
            vault=self.vault,
            detections=updated_detections,
            stats=stats
        )

    def desanitize(self, text: str, vault: Vault | None = None) -> str:
        """Restore original PII values from tokens.

        Args:
            text: Sanitized text with tokens
            vault: Vault containing mappings (uses internal vault if not provided)

        Returns:
            Text with original PII values restored
        """
        vault = vault or self.vault
        result_text = text

        for token, mapping in vault.get_all_mappings().items():
            result_text = result_text.replace(token, mapping.original)

        return result_text

    def sanitize_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Sanitize all string values in a dictionary recursively.

        Args:
            data: Dictionary to sanitize

        Returns:
            Sanitized dictionary with same structure
        """
        result: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized = self.sanitize(value)
                result[key] = sanitized.sanitized_text
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self.sanitize(item).sanitized_text if isinstance(item, str)
                    else self.sanitize_dict(item) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        return result

    def desanitize_dict(self, data: dict[str, Any], vault: Vault | None = None) -> dict[str, Any]:
        """Desanitize all string values in a dictionary recursively.

        Args:
            data: Dictionary with tokens to desanitize
            vault: Vault containing mappings

        Returns:
            Dictionary with original values restored
        """
        vault = vault or self.vault
        result: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.desanitize(value, vault)
            elif isinstance(value, dict):
                result[key] = self.desanitize_dict(value, vault)
            elif isinstance(value, list):
                result[key] = [
                    self.desanitize(item, vault) if isinstance(item, str)
                    else self.desanitize_dict(item, vault) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        return result


def create_engine(detectors: list[BaseDetector] | None = None) -> SanitizerEngine:
    """Factory function to create a sanitizer engine.

    Args:
        detectors: Optional custom detectors

    Returns:
        Configured SanitizerEngine instance
    """
    return SanitizerEngine(detectors)
