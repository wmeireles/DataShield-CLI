"""In-memory token registry with encrypted persistence."""

import json

from cryptography.fernet import Fernet
from pydantic import BaseModel, PrivateAttr


class TokenMapping(BaseModel):
    """Represents a token-to-PII mapping."""
    token: str
    original: str
    detector_name: str
    confidence: float = 1.0


class Vault(BaseModel):
    """Keep PII mappings in memory and seal them for optional persistence."""

    _mappings: dict[str, TokenMapping] = PrivateAttr(default_factory=dict)
    _reverse_index: dict[str, str] = PrivateAttr(default_factory=dict)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a URL-safe key for encrypted vault persistence."""
        return Fernet.generate_key()

    def store(self, token: str, original: str, detector_name: str, confidence: float = 1.0) -> None:
        """Store a token-to-original mapping.

        Args:
            token: The replacement token (e.g., '<CPF_1>')
            original: The original PII value
            detector_name: Name of the detector that found this PII
            confidence: Detection confidence score
        """
        # Check if original already has a token (deterministic mapping)
        if original in self._reverse_index:
            return

        if token in self._mappings:
            return

        mapping = TokenMapping(
            token=token,
            original=original,
            detector_name=detector_name,
            confidence=confidence
        )
        self._mappings[token] = mapping
        self._reverse_index[original] = token

    def retrieve(self, token: str) -> str | None:
        """Retrieve original PII value for a token.

        Args:
            token: The replacement token

        Returns:
            Original PII value or None if not found
        """
        mapping = self._mappings.get(token)
        return mapping.original if mapping else None

    def get_token_for(self, original: str) -> str | None:
        """Get existing token for an original value (for deterministic mapping).

        Args:
            original: The original PII value

        Returns:
            Existing token or None if not found
        """
        return self._reverse_index.get(original)

    def get_all_mappings(self) -> dict[str, TokenMapping]:
        """Get all token mappings (for desanitization)."""
        return self._mappings.copy()

    def export_encrypted(self, key: bytes) -> bytes:
        """Export mappings encrypted with a separately managed key.

        Returns:
            An authenticated Fernet token that does not contain the key.
        """
        data = {
            "version": 1,
            "mappings": {
                token: {
                    "original": mapping.original,
                    "detector_name": mapping.detector_name,
                    "confidence": mapping.confidence
                }
                for token, mapping in self._mappings.items()
            }
        }
        return Fernet(key).encrypt(json.dumps(data, separators=(",", ":")).encode())

    def import_encrypted(self, encrypted_data: bytes, key: bytes) -> None:
        """Import mappings from an authenticated encrypted payload.

        Args:
            encrypted_data: Previously exported encrypted data (with key)
            key: Separately managed Fernet key.
        """
        data = json.loads(Fernet(key).decrypt(encrypted_data).decode())
        if not isinstance(data, dict):
            raise ValueError("Unsupported or invalid vault payload")
        if data.get("version") != 1 or not isinstance(data.get("mappings"), dict):
            raise ValueError("Unsupported or invalid vault payload")
        # Validate the complete payload before changing the current vault.
        mappings: dict[str, TokenMapping] = {}
        reverse_index: dict[str, str] = {}
        for token, info in data["mappings"].items():
            if not isinstance(token, str) or not isinstance(info, dict):
                raise ValueError("Unsupported or invalid vault mapping")
            mapping = TokenMapping(
                token=token,
                original=info["original"],
                detector_name=info["detector_name"],
                confidence=info["confidence"]
            )
            if mapping.original in reverse_index:
                raise ValueError("Vault contains duplicate original values")
            mappings[token] = mapping
            reverse_index[mapping.original] = token

        self._mappings = mappings
        self._reverse_index = reverse_index

    def clear(self) -> None:
        """Clear all mappings from memory."""
        self._mappings.clear()
        self._reverse_index.clear()

    def __len__(self) -> int:
        return len(self._mappings)

    def __contains__(self, token: str) -> bool:
        return token in self._mappings
