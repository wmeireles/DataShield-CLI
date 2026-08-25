"""CNPJ (Cadastro Nacional da Pessoa Jurídica) detector with Modulo 11 validation."""

import re

from datashield.detectors.base import BaseDetector, Detection


class CNPJDetector(BaseDetector):
    """Detector for Brazilian CNPJ with mathematical validation.

    CNPJ format: XX.XXX.XXX/XXXX-XX or 14 digits
    Validation: Modulo 11 check-digit algorithm
    """

    _PATTERN_FORMATTED = re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b")
    _PATTERN_UNFORMATTED = re.compile(r"\b\d{14}\b")

    @property
    def name(self) -> str:
        return "cnpj"

    @property
    def token_prefix(self) -> str:
        return "CNPJ"

    def _calculate_check_digit(self, digits: list[int], weights: list[int]) -> int:
        """Calculate a single check digit using Modulo 11."""
        total = sum(d * w for d, w in zip(digits, weights, strict=True))
        remainder = total % 11
        return 0 if remainder < 2 else 11 - remainder

    def validate(self, candidate: str) -> bool:
        """Validate CNPJ using Modulo 11 algorithm.

        Args:
            candidate: CNPJ string (formatted or unformatted)

        Returns:
            True if valid CNPJ, False otherwise
        """
        digits_only = re.sub(r"\D", "", candidate)

        if len(digits_only) != 14:
            return False

        if len(set(digits_only)) == 1:
            return False

        digits = [int(d) for d in digits_only[:12]]

        weights_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
        check_1 = self._calculate_check_digit(digits, weights_1)

        if check_1 != int(digits_only[12]):
            return False

        digits.append(check_1)
        weights_2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
        check_2 = self._calculate_check_digit(digits, weights_2)

        return check_2 == int(digits_only[13])

    def find_candidates(self, text: str) -> list[str]:
        """Find all CNPJ candidates in text."""
        candidates = []

        for match in self._PATTERN_FORMATTED.finditer(text):
            candidates.append(match.group())

        for match in self._PATTERN_UNFORMATTED.finditer(text):
            candidate = match.group()
            if not self._is_part_of_formatted(text, match.start(), candidate):
                candidates.append(candidate)

        return candidates

    def _is_part_of_formatted(self, text: str, start: int, candidate: str) -> bool:
        """Check if unformatted candidate is part of a formatted CNPJ."""
        if start >= 3 and text[max(0, start - 5):start] in (".../.", "../.."):
            return True
        return start + 18 <= len(text) and text[start + 14:start + 18] in ("-.", "/..")

    def detect(self, text: str) -> list[Detection]:
        """Detect all valid CNPJs in text with position tracking."""
        detections: list[Detection] = []
        seen_positions: set[tuple[int, int]] = set()

        for match in self._PATTERN_FORMATTED.finditer(text):
            candidate = match.group()
            if self.validate(candidate) and (match.start(), match.end()) not in seen_positions:
                token = self.generate_token(len(detections) + 1)
                detections.append(Detection(
                    original=candidate,
                    token=token,
                    start=match.start(),
                    end=match.end(),
                    detector_name=self.name,
                    confidence=1.0
                ))
                seen_positions.add((match.start(), match.end()))

        for match in self._PATTERN_UNFORMATTED.finditer(text):
            candidate = match.group()
            if (match.start(), match.end()) in seen_positions:
                continue
            if self._is_part_of_formatted(text, match.start(), candidate):
                continue
            if self.validate(candidate):
                token = self.generate_token(len(detections) + 1)
                detections.append(Detection(
                    original=candidate,
                    token=token,
                    start=match.start(),
                    end=match.end(),
                    detector_name=self.name,
                    confidence=1.0
                ))

        detections.sort(key=lambda d: d.start, reverse=True)
        return detections
