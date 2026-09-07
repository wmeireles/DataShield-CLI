"""Tests for sanitizer engine."""

import pytest

from datashield.core.engine import SanitizeResult, create_engine
from datashield.detectors.br.cpf import CPFDetector


class TestSanitizerEngine:
    """Tests for SanitizerEngine."""

    @pytest.fixture
    def engine(self):
        return create_engine()

    def test_sanitize_empty_string(self, engine):
        """Test sanitizing empty string."""
        result = engine.sanitize("")
        assert result.sanitized_text == ""
        assert len(result.detections) == 0
        assert len(result.vault) == 0

    def test_sanitize_no_pii(self, engine):
        """Test sanitizing text with no PII."""
        text = "Olá, mundo! Este é um texto sem PII."
        result = engine.sanitize(text)
        assert result.sanitized_text == text
        assert len(result.detections) == 0

    def test_sanitize_single_cpf(self, engine):
        """Test sanitizing single CPF."""
        text = "Meu CPF é 111.444.777-35"
        result = engine.sanitize(text)
        assert result.sanitized_text == "Meu CPF é <CPF_1>"
        assert len(result.detections) == 1
        assert result.detections[0].original == "111.444.777-35"
        assert result.detections[0].token == "<CPF_1>"

    def test_sanitize_multiple_cpfs(self, engine):
        """Test sanitizing multiple different CPFs."""
        # 111.444.777-35 and 222.333.444-05 are valid CPFs
        text = "CPF1: 111.444.777-35 e CPF2: 222.333.444-05"
        result = engine.sanitize(text)
        assert "<CPF_1>" in result.sanitized_text
        assert "<CPF_2>" in result.sanitized_text
        assert len(result.detections) == 2

    def test_sanitize_duplicate_cpf_deterministic(self, engine):
        """Test same CPF gets same token."""
        text = "CPF: 111.444.777-35 e novamente: 111.444.777-35"
        result = engine.sanitize(text)
        assert result.sanitized_text.count("<CPF_1>") == 2
        assert "<CPF_2>" not in result.sanitized_text

    def test_sanitize_cpf_and_cnpj(self, engine):
        """Test sanitizing both CPF and CNPJ."""
        text = "CPF: 111.444.777-35, CNPJ: 11.222.333/0001-81"
        result = engine.sanitize(text)
        assert "<CPF_1>" in result.sanitized_text
        assert "<CNPJ_1>" in result.sanitized_text
        assert len(result.detections) == 2

    def test_sanitize_stats(self, engine):
        """Test sanitization stats."""
        text = "CPF: 111.444.777-35, CNPJ: 11.222.333/0001-81, Email: user@example.com"
        result = engine.sanitize(text)
        assert result.stats.get("cpf", 0) == 1
        assert result.stats.get("cnpj", 0) == 1
        assert result.stats.get("email", 0) == 1

    def test_desanitize(self, engine):
        """Test desanitization restores original values."""
        text = "CPF: 111.444.777-35"
        result = engine.sanitize(text)
        restored = engine.desanitize(result.sanitized_text, result.vault)
        assert restored == text

    def test_desanitize_with_external_vault(self, engine):
        """Test desanitize with externally provided vault."""
        text = "CPF: 111.444.777-35"
        result = engine.sanitize(text)

        new_engine = create_engine()
        restored = new_engine.desanitize(result.sanitized_text, result.vault)
        assert restored == text

    def test_sanitize_dict(self, engine):
        """Test sanitizing dictionary."""
        data = {
            "user": {
                "name": "João",
                "cpf": "111.444.777-35",
                "email": "joao@example.com"
            }
        }
        result = engine.sanitize_dict(data)
        assert result["user"]["cpf"] == "<CPF_1>"
        assert result["user"]["email"] == "<EMAIL_1>"
        assert result["user"]["name"] == "João"

    def test_sanitize_dict_nested(self, engine):
        """Test sanitizing nested dictionary."""
        data = {
            "users": [
                {"cpf": "111.444.777-35"},
                {"cpf": "222.333.444-05"}
            ]
        }
        result = engine.sanitize_dict(data)
        assert result["users"][0]["cpf"] == "<CPF_1>"
        assert result["users"][1]["cpf"] == "<CPF_2>"

    def test_desanitize_dict(self, engine):
        """Test desanitizing dictionary."""
        data = {"cpf": "111.444.777-35"}
        sanitized = engine.sanitize_dict(data)
        restored = engine.desanitize_dict(sanitized, engine.vault)
        assert restored == data

    def test_sanitize_result_dataclass(self):
        """Test SanitizeResult dataclass."""
        result = SanitizeResult(
            sanitized_text="test",
            vault=None,
            detections=[],
            stats={"cpf": 1}
        )
        assert result.sanitized_text == "test"
        assert result.stats["cpf"] == 1

    def test_custom_detectors(self):
        """Test engine with custom detectors."""
        custom_detectors = [CPFDetector()]
        engine = create_engine(custom_detectors)

        text = "CPF: 111.444.777-35 e CNPJ: 11.222.333/0001-81"
        result = engine.sanitize(text)

        # Only CPF should be detected
        assert "<CPF_1>" in result.sanitized_text
        assert "11.222.333/0001-81" in result.sanitized_text  # CNPJ not detected
        assert len(result.detections) == 1
        assert result.detections[0].detector_name == "cpf"


class TestSanitizerEngineEdgeCases:
    """Edge case tests for SanitizerEngine."""

    @pytest.fixture
    def engine(self):
        return create_engine()

    def test_overlapping_detections(self, engine):
        """Test handling of overlapping detections."""
        # This shouldn't happen with current detectors but test robustness
        text = "111.444.777-35"
        result = engine.sanitize(text)
        assert result.sanitized_text == "<CPF_1>"

    def test_unicode_text(self, engine):
        """Test sanitizing unicode text."""
        text = "CPF: 111.444.777-35 🎉 Olá 世界"
        result = engine.sanitize(text)
        assert result.sanitized_text == "CPF: <CPF_1> 🎉 Olá 世界"

    def test_newlines_and_tabs(self, engine):
        """Test sanitizing text with newlines and tabs."""
        text = "CPF:\t111.444.777-35\nCNPJ:\t11.222.333/0001-81"
        result = engine.sanitize(text)
        assert "<CPF_1>" in result.sanitized_text
        assert "<CNPJ_1>" in result.sanitized_text

    def test_vault_persists_across_calls(self, engine):
        """Test vault persists across multiple sanitize calls."""
        engine.sanitize("CPF: 111.444.777-35")
        result2 = engine.sanitize("Outro CPF: 111.444.777-35")

        # Same CPF should get same token
        assert result2.sanitized_text == "Outro CPF: <CPF_1>"
        assert len(engine.vault) == 1

    @pytest.mark.parametrize(
        ("text", "token"),
        [
            ("Emails: a@example.com e a@example.com", "<EMAIL_1>"),
            ("Telefones: (11) 99999-9999 e (11) 99999-9999", "<PHONE_1>"),
        ],
    )
    def test_repeated_values_are_replaced_at_each_position(self, engine, text, token):
        result = engine.sanitize(text)

        assert result.sanitized_text.count(token) == 2
        assert len(result.detections) == 2

    def test_large_text_performance(self, engine):
        """Test performance on larger text."""
        # Create text with many CPFs
        cpfs = [f"111.444.777-{i:02d}" for i in range(10)]
        # Only first few are valid, but test processing
        text = " ".join([f"CPF: {cpf}" for cpf in cpfs])

        result = engine.sanitize(text)
        # Should process without error
        assert isinstance(result.sanitized_text, str)
