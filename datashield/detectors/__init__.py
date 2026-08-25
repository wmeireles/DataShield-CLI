"""Detectors package for PII detection."""

from datashield.detectors.base import BaseDetector, Detection
from datashield.detectors.br.cnpj import CNPJDetector
from datashield.detectors.br.common import (
    APIKeyDetector,
    EmailDetector,
    PhoneDetector,
    get_br_detectors,
)
from datashield.detectors.br.cpf import CPFDetector

__all__ = [
    "APIKeyDetector",
    "BaseDetector",
    "CNPJDetector",
    "CPFDetector",
    "Detection",
    "EmailDetector",
    "PhoneDetector",
    "get_br_detectors",
]
