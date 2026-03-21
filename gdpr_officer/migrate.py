"""
Key migration utility.

Copies all customer keys from one backend to another. Use cases:
- Moving keys from local backend to a cloud backend.
- Migrating between cloud providers.
- Backing up keys to a secondary store.

Usage:
    from gdpr_officer import PiiEncryptor, migrate_keys

    local = PiiEncryptor(key_backend="local", key_backend_config={"db_path": "keys.duckdb"})
    prod = PiiEncryptor(key_backend="gcp_firestore", key_backend_config={"project": "my-proj"})
    migrate_keys(source=local, target=prod)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdpr_officer.api import PiiEncryptor

logger = logging.getLogger("gdpr_officer")


@dataclass
class MigrationResult:
    """Result of a key migration operation."""

    total_keys: int = 0
    migrated: int = 0
    skipped: int = 0
    errors: list[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


def migrate_keys(
    source: PiiEncryptor,
    target: PiiEncryptor,
    overwrite: bool = False,
) -> MigrationResult:
    """
    Copy all customer keys from source backend to target backend.

    Args:
        source: PiiEncryptor with the source key backend.
        target: PiiEncryptor with the target key backend.
        overwrite: If True, overwrite existing keys in target.
                   If False (default), skip customers that already have keys.

    Returns:
        MigrationResult with counts and any errors.
    """
    result = MigrationResult()

    customer_ids = source.list_active_customers()
    result.total_keys = len(customer_ids)

    logger.info(
        "Migrating %d keys from %s to %s",
        result.total_keys,
        source.backend_name,
        target.backend_name,
    )

    for cid in customer_ids:
        try:
            # Check if target already has this key
            if not overwrite:
                existing = target.backend.get_key(cid)
                if existing is not None:
                    result.skipped += 1
                    continue

            # Read key from source
            source_key = source.backend.get_key(cid)
            if source_key is None:
                result.errors.append(f"{cid}: key disappeared from source during migration")
                continue

            # Write the existing key bytes from source
            # instead of creating a new key
            _write_key_directly(target.backend, cid, source_key.key_bytes)
            result.migrated += 1

        except Exception as e:
            result.errors.append(f"{cid}: {e}")

    logger.info(
        "Migration complete: %d migrated, %d skipped, %d errors",
        result.migrated,
        result.skipped,
        len(result.errors),
    )

    return result


def _write_key_directly(backend, customer_id: str, key_bytes: bytes):
    """
    Write existing key bytes to a backend.

    Bypasses the create_key flow
    to preserve the exact key from the source during migration.
    """
    from gdpr_officer.backends.local import LocalKeystore

    # Local backend: direct insert
    if isinstance(backend, LocalKeystore):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        backend._conn.execute(
            "INSERT OR REPLACE INTO customer_keys (customer_id, key_bytes, created_at) "
            "VALUES (?, ?, ?)",
            [customer_id, key_bytes, now.isoformat()],
        )
        return

    # Cloud backends: try the _write_key method if available
    if hasattr(backend, "_keys"):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        backend._keys.document(customer_id).set({
            "key_bytes": key_bytes,
            "created_at": now.isoformat(),
        })
        return

    raise NotImplementedError(
        f"Direct key writing not supported for backend type {type(backend).__name__}. "
        "The backend needs to implement a migration-compatible write method."
    )
