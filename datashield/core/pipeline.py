"""High-level sanitization pipeline for text and structured content."""

from dataclasses import dataclass
from typing import Any, Literal, TypeAlias, cast

from datashield.core.engine import SanitizerEngine, create_engine
from datashield.core.vault import Vault
from datashield.detectors.base import Detection
from datashield.utils.formatters import (
    detect_format,
    parse_csv,
    parse_json,
    serialize_content,
)

InputFormat: TypeAlias = Literal["json", "csv", "text"]


@dataclass(frozen=True, slots=True)
class ProcessOutcome:
    """Observable result of processing one input payload."""

    content: str
    input_format: InputFormat
    detections: list[Detection]
    stats: dict[str, int]
    vault: Vault


class SanitizationPipeline:
    """Parse, sanitize and serialize content behind one interface."""

    def __init__(self, engine: SanitizerEngine | None = None) -> None:
        self._engine = engine or create_engine()

    def process(
        self,
        content: str,
        *,
        input_format: InputFormat | None = None,
        filename: str = "",
    ) -> ProcessOutcome:
        """Sanitize content while preserving its detected or requested format."""
        resolved_format = cast(InputFormat, input_format or detect_format(content, filename))
        data = self._parse(content, resolved_format)
        detections: list[Detection] = []
        sanitized = self._sanitize_value(data, detections)
        output = sanitized if isinstance(sanitized, str) else serialize_content(
            sanitized, resolved_format
        )
        stats: dict[str, int] = {}
        for detection in detections:
            stats[detection.detector_name] = stats.get(detection.detector_name, 0) + 1
        return ProcessOutcome(
            content=output,
            input_format=resolved_format,
            detections=detections,
            stats=stats,
            vault=self._engine.vault,
        )

    @staticmethod
    def _parse(content: str, input_format: InputFormat) -> Any:
        if input_format == "json":
            return parse_json(content)
        if input_format == "csv":
            return parse_csv(content)
        return content

    def _sanitize_value(self, value: Any, detections: list[Detection]) -> Any:
        if isinstance(value, str):
            result = self._engine.sanitize(value)
            detections.extend(result.detections)
            return result.sanitized_text
        if isinstance(value, dict):
            return {key: self._sanitize_value(item, detections) for key, item in value.items()}
        if isinstance(value, list):
            return [self._sanitize_value(item, detections) for item in value]
        return value

