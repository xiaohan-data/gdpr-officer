"""
Core PII encryption engine.

Uses AES-256-GCM for column-level encryption. 
Each encrypted value is a base64-encoded string containing a version prefix, random nonce, and ciphertext.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gdpr_officer.config import GdprOfficerConfig, SourceConfig
from gdpr_officer.key_backend import CustomerKey, KeyBackend

_NONCE_SIZE = 12
_ENCRYPTED_PREFIX = b"gdpr-officer:v1:"


@dataclass
class EncryptionResult:
    """Result of encrypting a single row."""

    row: dict[str, Any]
    customer_id: str
    encrypted_columns: list[str]
    key_created: bool = False


@dataclass
class BatchResult:
    """Result of encrypting a batch of rows."""

    rows: list[dict[str, Any]]
    total_rows: int = 0
    encrypted_rows: int = 0
    skipped_rows: int = 0
    new_keys_created: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)


class EncryptionEngine:
    """
    Encrypts PII columns in data rows using per-customer symmetric keys.
    """

    def __init__(self, key_backend: KeyBackend, config: GdprOfficerConfig):
        self._backend = key_backend
        self._config = config
        self._key_cache: dict[str, CustomerKey] = {}

    def encrypt_value(self, plaintext: str, key: CustomerKey) -> str:
        """Encrypt a single string value using AES-256-GCM."""
        if not plaintext:
            return plaintext

        nonce = os.urandom(_NONCE_SIZE)
        aesgcm = AESGCM(key.key_bytes)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        packed = _ENCRYPTED_PREFIX + nonce + ciphertext
        return base64.b64encode(packed).decode("ascii")

    def decrypt_value(self, encrypted: str, key: CustomerKey) -> str:
        """Decrypt a single value encrypted by this engine."""
        packed = base64.b64decode(encrypted.encode("ascii"))

        if not packed.startswith(_ENCRYPTED_PREFIX):
            raise ValueError("Value was not encrypted by gdpr-officer")

        payload = packed[len(_ENCRYPTED_PREFIX):]
        nonce = payload[:_NONCE_SIZE]
        ciphertext = payload[_NONCE_SIZE:]

        aesgcm = AESGCM(key.key_bytes)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    def encrypt_row(self, row: dict[str, Any], source: SourceConfig) -> EncryptionResult:
        """Encrypt PII columns in a single row."""
        customer_id = str(row.get(source.customer_id_column, ""))
        if not customer_id:
            raise ValueError(
                f"Row missing customer ID column '{source.customer_id_column}'"
            )

        key_created = False
        if customer_id in self._key_cache:
            key = self._key_cache[customer_id]
        else:
            existing = self._backend.get_key(customer_id)
            if existing is not None:
                key = existing
            else:
                key = self._backend.create_key(customer_id)
                key_created = True
            self._key_cache[customer_id] = key

        encrypted_row = dict(row)
        encrypted_columns = []

        for col in source.pii_columns:
            if col in encrypted_row and encrypted_row[col] is not None:
                encrypted_row[col] = self.encrypt_value(str(encrypted_row[col]), key)
                encrypted_columns.append(col)

        return EncryptionResult(
            row=encrypted_row,
            customer_id=customer_id,
            encrypted_columns=encrypted_columns,
            key_created=key_created,
        )

    def encrypt_batch(self, rows: list[dict[str, Any]], source: SourceConfig) -> BatchResult:
        """Encrypt PII columns in a batch of rows with optimised key fetching."""
        result = BatchResult(rows=[], total_rows=len(rows))

        customer_ids = list({
            str(row.get(source.customer_id_column, ""))
            for row in rows
            if row.get(source.customer_id_column)
        })

        keys = self._backend.batch_get_or_create(customer_ids)
        new_keys = sum(1 for cid in customer_ids if cid not in self._key_cache)
        self._key_cache.update(keys)
        result.new_keys_created = new_keys

        for i, row in enumerate(rows):
            try:
                encrypted = self.encrypt_row(row, source)
                result.rows.append(encrypted.row)
                result.encrypted_rows += 1
            except Exception as e:
                result.errors.append({"row_index": i, "error": str(e)})
                result.skipped_rows += 1

        return result

    def decrypt_row(self, row: dict[str, Any], source: SourceConfig) -> dict[str, Any]:
        """Decrypt PII columns. Raises KeyError if customer has been forgotten."""
        customer_id = str(row.get(source.customer_id_column, ""))
        key = self._backend.get_key(customer_id)

        if key is None:
            raise KeyError(
                f"No key for customer '{customer_id}'. "
                "Customer may have been cryptographically erased."
            )

        decrypted_row = dict(row)
        for col in source.pii_columns:
            if col in decrypted_row and decrypted_row[col] is not None:
                try:
                    decrypted_row[col] = self.decrypt_value(str(decrypted_row[col]), key)
                except ValueError:
                    # Value not encrypted, leave as-is.
                    pass
                except InvalidTag:
                    # Value encrypted with a different key (previously forgotten), unrecoverable, leave as-is.
                    pass

        return decrypted_row

    def clear_cache(self):
        self._key_cache.clear()
