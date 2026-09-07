"""Behavior tests for the sanitization pipeline interface."""

import orjson

from datashield.core.pipeline import SanitizationPipeline


def test_pipeline_sanitizes_structured_content_and_reports_detections():
    pipeline = SanitizationPipeline()

    outcome = pipeline.process(
        '{"users":[{"cpf":"111.444.777-35"},{"email":"a@example.com"}]}',
        input_format="json",
    )

    assert orjson.loads(outcome.content) == {
        "users": [{"cpf": "<CPF_1>"}, {"email": "<EMAIL_1>"}]
    }
    assert outcome.input_format == "json"
    assert outcome.stats == {"cpf": 1, "email": 1}
    assert len(outcome.detections) == 2


def test_pipeline_keeps_only_the_longest_overlapping_detection():
    pipeline = SanitizationPipeline()

    outcome = pipeline.process("id=10900002000", input_format="text")

    assert outcome.content == "id=<CPF_1>"
    assert outcome.stats == {"cpf": 1}
    assert len(outcome.detections) == 1
