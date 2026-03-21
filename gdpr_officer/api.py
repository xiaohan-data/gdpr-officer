"""
High-level API for gdpr-officer.

Usage:
    from gdpr_officer import PiiEncryptor

    officer = PiiEncryptor(
        key_backend="gcp_firestore",
        key_backend_config={"project": "my-project"},
    )

    df = officer.encrypt_df(df, customer_id="customer_id", pii=["email", "phone"])
    officer.forget("customer-123", reason="GDPR Art.17", requested_by="dpo@co.com")
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import gdpr_officer.backends  # noqa: F401 — register backends
from gdpr_officer.config import GdprOfficerConfig, SourceConfig
from gdpr_officer.encryptor import BatchResult, EncryptionEngine
from gdpr_officer.key_backend import DeletionRecord, KeyBackend, get_backend


class PiiEncryptor:
    """
    Per-customer PII encryption for data pipelines.

    Two ways to initialise:

        # Direct
        officer = PiiEncryptor(
            key_backend="gcp_firestore",
            key_backend_config={"project": "my-project"},
        )

        # From YAML config
        officer = PiiEncryptor.from_config("gdpr_officer.yaml")
    """

    def __init__(
        self,
        key_backend: str = "local",
        key_backend_config: dict[str, Any] | None = None,
        *,
        _config: GdprOfficerConfig | None = None,
    ):
        if _config is not None:
            self._config = _config
        else:
            self._config = GdprOfficerConfig(
                key_backend=key_backend,
                key_backend_config=key_backend_config or {},
            )

        self._backend: KeyBackend = get_backend(
            self._config.key_backend, **self._config.key_backend_config
        )
        self._engine = EncryptionEngine(self._backend, self._config)

    @classmethod
    def from_config(cls, path: str | Path) -> PiiEncryptor:
        config = GdprOfficerConfig.from_yaml(path)
        return cls(_config=config)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PiiEncryptor:
        config = GdprOfficerConfig.from_dict(data)
        return cls(_config=config)

    # ── DataFrame API ───────────────────────────────────────────────

    def encrypt_df(self, df: Any, customer_id: str, pii: list[str]) -> Any:
        """
        Encrypt PII columns in a pandas DataFrame. Returns a new DataFrame.

        Example:
            df = officer.encrypt_df(df, customer_id="patient_number", pii=["ssn", "address"])
        """
        import pandas as pd

        source = SourceConfig(name="_inline", customer_id_column=customer_id, pii_columns=pii)
        rows = df.to_dict(orient="records")
        result = self._engine.encrypt_batch(rows, source)

        if result.errors:
            raise RuntimeError(
                f"Encryption failed for {len(result.errors)}/{result.total_rows} rows. "
                f"First error: {result.errors[0]['error']}"
            )

        return pd.DataFrame(result.rows, columns=df.columns)

    def decrypt_df(self, df: Any, customer_id: str, pii: list[str]) -> Any:
        """
        Decrypt PII columns. Forgotten customers' PII is left as encrypted values.
        """
        import pandas as pd

        source = SourceConfig(name="_inline", customer_id_column=customer_id, pii_columns=pii)
        decrypted = []
        for row in df.to_dict(orient="records"):
            try:
                decrypted.append(self._engine.decrypt_row(row, source))
            except KeyError:
                decrypted.append(row)

        return pd.DataFrame(decrypted, columns=df.columns)

    # ── Row/dict API ────────────────────────────────────────────────

    def encrypt_rows(
        self, rows: list[dict[str, Any]], customer_id: str, pii: list[str]
    ) -> list[dict[str, Any]]:
        """Encrypt PII columns in a list of row dicts."""
        source = SourceConfig(name="_inline", customer_id_column=customer_id, pii_columns=pii)
        result = self._engine.encrypt_batch(rows, source)
        if result.errors:
            raise RuntimeError(
                f"Encryption failed for {len(result.errors)}/{result.total_rows} rows. "
                f"First error: {result.errors[0]['error']}"
            )
        return result.rows

    def encrypt_row(
        self, row: dict[str, Any], customer_id: str, pii: list[str]
    ) -> dict[str, Any]:
        """Encrypt PII columns in a single row dict."""
        source = SourceConfig(name="_inline", customer_id_column=customer_id, pii_columns=pii)
        return self._engine.encrypt_row(row, source).row

    def decrypt_row(
        self, row: dict[str, Any], customer_id: str, pii: list[str]
    ) -> dict[str, Any]:
        """Decrypt PII columns. Raises KeyError if customer was forgotten."""
        source = SourceConfig(name="_inline", customer_id_column=customer_id, pii_columns=pii)
        return self._engine.decrypt_row(row, source)

    # ── Named source API (config-file workflow) ─────────────────────

    def encrypt(self, row: dict[str, Any], source: str) -> dict[str, Any]:
        source_config = self._config.get_source(source)
        return self._engine.encrypt_row(row, source_config).row

    def encrypt_batch(self, rows: list[dict[str, Any]], source: str) -> BatchResult:
        source_config = self._config.get_source(source)
        return self._engine.encrypt_batch(rows, source_config)

    def decrypt(self, row: dict[str, Any], source: str) -> dict[str, Any]:
        source_config = self._config.get_source(source)
        return self._engine.decrypt_row(row, source_config)

    # ── GDPR Lifecycle ──────────────────────────────────────────────

    def forget(self, customer_id: str, reason: str, requested_by: str) -> DeletionRecord:
        """
        Cryptographically erase a customer by deleting their key.

        After this, all PII encrypted with this key across every table
        in the warehouse is permanently unrecoverable.
        """
        self._engine.clear_cache()
        return self._backend.delete_key(customer_id, reason, requested_by)

    def is_forgotten(self, customer_id: str) -> bool:
        return self._backend.get_key(customer_id) is None

    def list_active_customers(self) -> list[str]:
        return self._backend.list_customers()

    def get_deletion_log(self) -> list[DeletionRecord]:
        return self._backend.get_deletion_log()

    # ── Access to internals ─────────────────────────────────────────

    @property
    def backend(self) -> KeyBackend:
        """Direct access to the key backend (for migration, export, etc.)."""
        return self._backend

    @property
    def config(self) -> GdprOfficerConfig:
        return self._config

    @property
    def backend_name(self) -> str:
        return self._config.key_backend
