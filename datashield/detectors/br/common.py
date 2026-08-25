"""Common PII detectors: Email, Phone, API Key."""

import re
from typing import ClassVar

from datashield.detectors.base import BaseDetector, Detection


class EmailDetector(BaseDetector):
    """Detector for email addresses using RFC 5322 compliant pattern."""

    _PATTERN = re.compile(
        r"\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b"
    )

    @property
    def name(self) -> str:
        return "email"

    @property
    def token_prefix(self) -> str:
        return "EMAIL"

    def validate(self, candidate: str) -> bool:
        """Basic email validation."""
        if candidate.count("@") != 1:
            return False
        local, domain = candidate.split("@")
        if not local or not domain:
            return False
        if domain.startswith(".") or domain.endswith("."):
            return False
        return ".." not in domain

    def find_candidates(self, text: str) -> list[str]:
        return [m.group() for m in self._PATTERN.finditer(text)]


class PhoneDetector(BaseDetector):
    """Detector for Brazilian phone numbers."""

    _PATTERN = re.compile(
        r"(?:\+55\s?)?"
        r"(?:\(?\d{2}\)?\s?)?"
        r"(?:9\s?)?"
        r"\d{4}[-\s]?\d{4}\b"
    )

    @property
    def name(self) -> str:
        return "phone"

    @property
    def token_prefix(self) -> str:
        return "PHONE"

    def validate(self, candidate: str) -> bool:
        """Validate Brazilian phone number (mobile only)."""
        digits = re.sub(r"\D", "", candidate)
        if len(digits) not in (11, 12, 13):
            return False
        return digits[-9] == "9"

    def find_candidates(self, text: str) -> list[str]:
        return [m.group() for m in self._PATTERN.finditer(text)]


class APIKeyDetector(BaseDetector):
    """Detector for API keys and bearer tokens."""

    _PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"\bsk-[a-zA-Z0-9]{48}\b"),  # OpenAI
        re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{95}\b"),  # Anthropic
        re.compile(
            r"\b[Aa][Pp][Ii][-_]?[Kk][Ee][Yy][\s:=]+['\"]?"
            r"[a-zA-Z0-9_-]{20,}['\"]?"
        ),  # Generic API key
        re.compile(r"\bBearer\s+[a-zA-Z0-9_-]{20,}\b"),  # Bearer token
        re.compile(r"\baws_access_key_id\s*=\s*[A-Z0-9]{20}\b"),  # AWS
        re.compile(r"\baws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}\b"),  # AWS secret
        re.compile(r"\bgh[pousr]_[a-zA-Z0-9]{36,}\b"),  # GitHub tokens
        re.compile(r"\b[a-zA-Z0-9_-]{32,}\b"),  # High entropy strings
    ]

    @property
    def name(self) -> str:
        return "api_key"

    @property
    def token_prefix(self) -> str:
        return "API_KEY"

    def validate(self, candidate: str) -> bool:
        """Validate API key using entropy and pattern checks."""
        if len(candidate) < 20:
            return False
        unique_chars = len(set(candidate))
        return not unique_chars < 10

    def find_candidates(self, text: str) -> list[str]:
        candidates = []
        for pattern in self._PATTERNS:
            for match in pattern.finditer(text):
                candidates.append(match.group())
        return candidates

    def detect(self, text: str) -> list[Detection]:
        """Detect API keys with deduplication."""
        detections: list[Detection] = []
        seen_spans: set[tuple[int, int]] = set()

        for pattern in self._PATTERNS:
            for match in pattern.finditer(text):
                candidate = match.group()
                span = (match.start(), match.end())
                if span in seen_spans:
                    continue
                if self.validate(candidate):
                    token = self.generate_token(len(detections) + 1)
                    detections.append(Detection(
                        original=candidate,
                        token=token,
                        start=match.start(),
                        end=match.end(),
                        detector_name=self.name,
                        confidence=0.9
                    ))
                    seen_spans.add(span)

        detections.sort(key=lambda d: d.start, reverse=True)
        return detections


def get_br_detectors() -> list[BaseDetector]:
    """Get all Brazilian detectors."""
    from datashield.detectors.br.cnpj import CNPJDetector
    from datashield.detectors.br.cpf import CPFDetector

    return [
        CPFDetector(),
        CNPJDetector(),
        EmailDetector(),
        PhoneDetector(),
        APIKeyDetector(),
    ]
