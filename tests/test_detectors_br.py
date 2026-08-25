"""Tests for Brazilian PII detectors."""

import pytest

from datashield.detectors.br.cnpj import CNPJDetector
from datashield.detectors.br.common import APIKeyDetector, EmailDetector, PhoneDetector
from datashield.detectors.br.cpf import CPFDetector


class TestCPFDetector:
    """Tests for CPF detector with Modulo 11 validation."""

    @pytest.fixture
    def detector(self):
        return CPFDetector()

    def test_valid_cpf_formatted(self, detector):
        """Test valid formatted CPF."""
        # Valid CPF: 111.444.777-35
        cpf = "111.444.777-35"
        assert detector.validate(cpf) is True

    def test_valid_cpf_unformatted(self, detector):
        """Test valid unformatted CPF."""
        cpf = "11144477735"
        assert detector.validate(cpf) is True

    def test_invalid_cpf_check_digit(self, detector):
        """Test CPF with invalid check digit."""
        cpf = "111.444.777-36"
        assert detector.validate(cpf) is False

    def test_invalid_cpf_all_same_digits(self, detector):
        """Test CPF with all same digits (invalid)."""
        cpf = "111.111.111-11"
        assert detector.validate(cpf) is False

    def test_invalid_cpf_wrong_length(self, detector):
        """Test CPF with wrong length."""
        cpf = "123.456.789-0"
        assert detector.validate(cpf) is False

    def test_detect_single_cpf(self, detector):
        """Test detection of single CPF in text."""
        text = "Meu CPF é 111.444.777-35"
        detections = detector.detect(text)
        assert len(detections) == 1
        assert detections[0].original == "111.444.777-35"
        assert detections[0].token == "<CPF_1>"
        assert detections[0].detector_name == "cpf"

    def test_detect_multiple_cpfs(self, detector):
        """Test detection of multiple CPFs."""
        text = "CPF1: 111.444.777-35 e CPF2: 111.444.777-35"
        detections = detector.detect(text)
        assert len(detections) == 2

    def test_detect_cpf_in_json(self, detector):
        """Test CPF detection in JSON-like text."""
        text = '{"user": {"cpf": "11144477735"}}'
        detections = detector.detect(text)
        assert len(detections) == 1
        assert detections[0].original == "11144477735"

    def test_no_false_positive_on_similar_numbers(self, detector):
        """Test no false positive on similar but invalid numbers."""
        text = "Telefone: 11987654321"
        detections = detector.detect(text)
        assert len(detections) == 0


class TestCNPJDetector:
    """Tests for CNPJ detector with Modulo 11 validation."""

    @pytest.fixture
    def detector(self):
        return CNPJDetector()

    def test_valid_cnpj_formatted(self, detector):
        """Test valid formatted CNPJ."""
        # Valid CNPJ: 11.222.333/0001-81
        cnpj = "11.222.333/0001-81"
        assert detector.validate(cnpj) is True

    def test_valid_cnpj_unformatted(self, detector):
        """Test valid unformatted CNPJ."""
        cnpj = "11222333000181"
        assert detector.validate(cnpj) is True

    def test_invalid_cnpj_check_digit(self, detector):
        """Test CNPJ with invalid check digit."""
        cnpj = "11.222.333/0001-82"
        assert detector.validate(cnpj) is False

    def test_invalid_cnpj_all_same_digits(self, detector):
        """Test CNPJ with all same digits (invalid)."""
        cnpj = "11.111.111/1111-11"
        assert detector.validate(cnpj) is False

    def test_invalid_cnpj_wrong_length(self, detector):
        """Test CNPJ with wrong length."""
        cnpj = "12.345.678/9012-3"
        assert detector.validate(cnpj) is False

    def test_detect_single_cnpj(self, detector):
        """Test detection of single CNPJ in text."""
        text = "CNPJ da empresa: 11.222.333/0001-81"
        detections = detector.detect(text)
        assert len(detections) == 1
        assert detections[0].original == "11.222.333/0001-81"
        assert detections[0].token == "<CNPJ_1>"

    def test_detect_multiple_cnpjs(self, detector):
        """Test detection of multiple CNPJs."""
        text = "CNPJ1: 11.222.333/0001-81 e CNPJ2: 11.222.333/0001-81"
        detections = detector.detect(text)
        assert len(detections) == 2


class TestEmailDetector:
    """Tests for Email detector."""

    @pytest.fixture
    def detector(self):
        return EmailDetector()

    def test_valid_emails(self, detector):
        """Test various valid email formats."""
        valid_emails = [
            "user@example.com",
            "user.name@example.com",
            "user+tag@example.co.uk",
            "user_name@example-domain.com",
            "user123@sub.domain.example.com",
        ]
        for email in valid_emails:
            assert detector.validate(email) is True, f"Failed for {email}"

    def test_invalid_emails(self, detector):
        """Test invalid email formats."""
        invalid_emails = [
            "userexample.com",  # Missing @
            "@example.com",  # Missing local part
            "user@",  # Missing domain
            "user@.com",  # Domain starts with dot
            "user@com.",  # Domain ends with dot
            "user@@example.com",  # Double @
        ]
        for email in invalid_emails:
            assert detector.validate(email) is False, f"Should fail for {email}"

    def test_detect_email_in_text(self, detector):
        """Test email detection in text."""
        text = "Contato: usuario@exemplo.com.br"
        detections = detector.detect(text)
        assert len(detections) == 1
        assert detections[0].original == "usuario@exemplo.com.br"
        assert detections[0].token == "<EMAIL_1>"


class TestPhoneDetector:
    """Tests for Brazilian Phone detector."""

    @pytest.fixture
    def detector(self):
        return PhoneDetector()

    def test_valid_phones(self, detector):
        """Test valid Brazilian phone formats."""
        valid_phones = [
            "(11) 99999-9999",
            "11 99999-9999",
            "+55 11 99999-9999",
            "11999999999",
            "(11) 98765-4321",
        ]
        for phone in valid_phones:
            assert detector.validate(phone) is True, f"Failed for {phone}"

    def test_invalid_phones(self, detector):
        """Test invalid phone formats."""
        invalid_phones = [
            "123456789",  # Too short
            "(11) 8999-9999",  # Not a mobile (no 9)
            "11 89999-9999",  # Not a mobile
        ]
        for phone in invalid_phones:
            assert detector.validate(phone) is False, f"Should fail for {phone}"

    def test_detect_phone_in_text(self, detector):
        """Test phone detection in text."""
        text = "Ligue para (11) 99999-9999"
        detections = detector.detect(text)
        assert len(detections) == 1
        assert detections[0].token == "<PHONE_1>"


class TestAPIKeyDetector:
    """Tests for API Key detector."""

    @pytest.fixture
    def detector(self):
        return APIKeyDetector()

    def test_openai_key(self, detector):
        """Test OpenAI API key detection."""
        key = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
        assert detector.validate(key) is True

    def test_anthropic_key(self, detector):
        """Test Anthropic API key detection."""
        key = "sk-ant-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz123456"
        assert detector.validate(key) is True

    def test_bearer_token(self, detector):
        """Test Bearer token detection."""
        token = "Bearer abcdefghijklmnopqrstuvwxyz123456"
        assert detector.validate(token) is True

    def test_generic_api_key(self, detector):
        """Test generic API key pattern."""
        key = "api_key=abcdefghijklmnopqrstuvwxyz123456"
        assert detector.validate(key) is True

    def test_low_entropy_rejected(self, detector):
        """Test low entropy strings are rejected."""
        low_entropy = "aaaaaaaaaaaaaaaaaaaa"
        assert detector.validate(low_entropy) is False

    def test_short_key_rejected(self, detector):
        """Test short keys are rejected."""
        short = "sk-short"
        assert detector.validate(short) is False

    def test_detect_api_key_in_text(self, detector):
        """Test API key detection in text."""
        text = "Use this key: sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
        detections = detector.detect(text)
        assert len(detections) == 1
        assert detections[0].token == "<API_KEY_1>"


class TestDetectorIntegration:
    """Integration tests for multiple detectors."""

    def test_cpf_and_cnpj_together(self):
        """Test CPF and CNPJ detection together."""
        from datashield.detectors.br.common import get_br_detectors

        detectors = get_br_detectors()
        text = "CPF: 111.444.777-35, CNPJ: 11.222.333/0001-81"

        all_detections = []
        for detector in detectors:
            all_detections.extend(detector.detect(text))

        cpf_detections = [d for d in all_detections if d.detector_name == "cpf"]
        cnpj_detections = [d for d in all_detections if d.detector_name == "cnpj"]

        assert len(cpf_detections) == 1
        assert len(cnpj_detections) == 1

    def test_deterministic_tokens(self):
        """Test that same PII gets same token."""
        from datashield.core.engine import create_engine

        engine = create_engine()
        text = "CPF: 111.444.777-35 e outro CPF: 111.444.777-35"
        result = engine.sanitize(text)

        # Both occurrences should have same token
        assert result.sanitized_text.count("<CPF_1>") == 2
        assert "<CPF_2>" not in result.sanitized_text
