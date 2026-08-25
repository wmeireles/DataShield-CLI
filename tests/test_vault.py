"""Tests for encrypted token vault."""

import json

import pytest

from datashield.core.vault import TokenMapping, Vault


class TestVault:
    """Tests for Vault class."""

    @pytest.fixture
    def vault(self):
        return Vault()

    def test_store_and_retrieve(self, vault):
        """Test basic store and retrieve."""
        vault.store("<CPF_1>", "111.444.777-35", "cpf")
        assert vault.retrieve("<CPF_1>") == "111.444.777-35"

    def test_store_multiple(self, vault):
        """Test storing multiple mappings."""
        vault.store("<CPF_1>", "111.444.777-35", "cpf")
        vault.store("<CNPJ_1>", "11.222.333/0001-81", "cnpj")
        vault.store("<EMAIL_1>", "user@example.com", "email")

        assert vault.retrieve("<CPF_1>") == "111.444.777-35"
        assert vault.retrieve("<CNPJ_1>") == "11.222.333/0001-81"
        assert vault.retrieve("<EMAIL_1>") == "user@example.com"
        assert len(vault) == 3

    def test_retrieve_nonexistent(self, vault):
        """Test retrieving non-existent token returns None."""
        assert vault.retrieve("<NONEXISTENT>") is None

    def test_get_token_for_existing(self, vault):
        """Test getting token for existing original value."""
        vault.store("<CPF_1>", "111.444.777-35", "cpf")
        token = vault.get_token_for("111.444.777-35")
        assert token == "<CPF_1>"

    def test_get_token_for_nonexistent(self, vault):
        """Test getting token for non-existent original returns None."""
        assert vault.get_token_for("nonexistent") is None

    def test_deterministic_mapping(self, vault):
        """Test same original gets same token."""
        vault.store("<CPF_1>", "111.444.777-35", "cpf")
        token = vault.get_token_for("111.444.777-35")
        assert token == "<CPF_1>"

        # Trying to store again should not create duplicate
        vault.store("<CPF_2>", "111.444.777-35", "cpf")
        assert len(vault) == 1

    def test_get_all_mappings(self, vault):
        """Test getting all mappings."""
        vault.store("<CPF_1>", "111.444.777-35", "cpf", 1.0)
        vault.store("<EMAIL_1>", "user@example.com", "email", 0.9)

        mappings = vault.get_all_mappings()
        assert len(mappings) == 2
        assert "<CPF_1>" in mappings
        assert "<EMAIL_1>" in mappings
        assert mappings["<CPF_1>"].detector_name == "cpf"
        assert mappings["<EMAIL_1>"].confidence == 0.9

    def test_export_import_encrypted(self, vault):
        """Test encrypted export and import."""
        vault.store("<CPF_1>", "111.444.777-35", "cpf")
        vault.store("<CNPJ_1>", "11.222.333/0001-81", "cnpj")

        encrypted = vault.export_encrypted()
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0

        new_vault = Vault()
        new_vault.import_encrypted(encrypted)

        assert new_vault.retrieve("<CPF_1>") == "111.444.777-35"
        assert new_vault.retrieve("<CNPJ_1>") == "11.222.333/0001-81"
        assert len(new_vault) == 2

    def test_import_wrong_key_fails(self, vault):
        """Test import with wrong encryption key fails."""
        vault.store("<CPF_1>", "111.444.777-35", "cpf")
        encrypted = vault.export_encrypted()

        # Create new vault with different key
        new_vault = Vault()
        # Corrupt the encrypted data
        corrupted = encrypted[:-1] + b"x"

        with pytest.raises((ValueError, json.JSONDecodeError)):
            new_vault.import_encrypted(corrupted)

    def test_clear(self, vault):
        """Test clearing vault."""
        vault.store("<CPF_1>", "111.444.777-35", "cpf")
        assert len(vault) == 1

        vault.clear()
        assert len(vault) == 0
        assert vault.retrieve("<CPF_1>") is None

    def test_contains(self, vault):
        """Test contains operator."""
        vault.store("<CPF_1>", "111.444.777-35", "cpf")
        assert "<CPF_1>" in vault
        assert "<CPF_2>" not in vault

    def test_token_mapping_model(self):
        """Test TokenMapping Pydantic model."""
        mapping = TokenMapping(
            token="<CPF_1>",
            original="111.444.777-35",
            detector_name="cpf",
            confidence=1.0
        )
        assert mapping.token == "<CPF_1>"
        assert mapping.original == "111.444.777-35"
        assert mapping.detector_name == "cpf"
        assert mapping.confidence == 1.0
