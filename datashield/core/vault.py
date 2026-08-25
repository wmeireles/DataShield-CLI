"""Encrypted in-memory token vault for PII mappings."""


from cryptography.fernet import Fernet
from pydantic import BaseModel, PrivateAttr


class TokenMapping(BaseModel):
    """Represents a token-to-PII mapping."""
    token: str
    original: str
    detector_name: str
    confidence: float = 1.0


class Vault(BaseModel):
    """Encrypted in-memory vault for PII token mappings.

    Uses Fernet symmetric encryption (AES-256) with a session-bound key.
    All mappings are encrypted in memory and never persisted to disk.
    """

    _fernet: Fernet = PrivateAttr(default_factory=lambda: Fernet(Fernet.generate_key()))
    _mappings: dict[str, TokenMapping] = PrivateAttr(default_factory=dict)
    _reverse_index: dict[str, str] = PrivateAttr(default_factory=dict)

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

    def export_encrypted(self) -> bytes:
        """Export all mappings as encrypted bytes for session persistence.

        Returns:
            Encrypted bytes containing all mappings and the encryption key
        """
        import base64
        import json
        key_bytes = self._fernet._signing_key + self._fernet._encryption_key
        encoded_key = base64.b64encode(key_bytes).decode()
        data = {
            "key": encoded_key,
            "mappings": {
                token: {
                    "original": mapping.original,
                    "detector_name": mapping.detector_name,
                    "confidence": mapping.confidence
                }
                for token, mapping in self._mappings.items()
            }
        }
        json_data = json.dumps(data).encode()
        return json_data

    def import_encrypted(self, encrypted_data: bytes) -> None:
        """Import mappings from encrypted bytes.

        Args:
            encrypted_data: Previously exported encrypted data (with key)
        """
        import base64
        import json

        from cryptography.fernet import Fernet

        data = json.loads(encrypted_data.decode())

        # Restore the Fernet key
        key_bytes = base64.b64decode(data["key"])
        signing_key = key_bytes[:32]
        encryption_key = key_bytes[32:]
        self._fernet = Fernet(base64.b64encode(signing_key + encryption_key).decode().encode())

        self._mappings.clear()
        self._reverse_index.clear()

        for token, info in data["mappings"].items():
            mapping = TokenMapping(
                token=token,
                original=info["original"],
                detector_name=info["detector_name"],
                confidence=info["confidence"]
            )
            self._mappings[token] = mapping
            self._reverse_index[info["original"]] = token

    def clear(self) -> None:
        """Clear all mappings from memory."""
        self._mappings.clear()
        self._reverse_index.clear()

    def __len__(self) -> int:
        return len(self._mappings)

    def __contains__(self, token: str) -> bool:
        return token in self._mappings
