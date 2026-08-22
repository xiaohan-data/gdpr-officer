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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from gdpr_officer.exceptions import KeyExistsError
from gdpr_officer.key_backend import KeyBackend

if TYPE_CHECKING:
    from gdpr_officer.api import PiiEncryptor

logger = logging.getLogger("gdpr_officer")


@dataclass
class MigrationResult:
    """Result of a key migration operation."""

    total_keys: int = 0
    migrated: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


def migrate_keys(source: PiiEncryptor, target: PiiEncryptor) -> MigrationResult:
    """
    Copy all customer keys from source backend to target backend.

    Keys are written as is: the key bytes and the original creation time are preserved.
    An existing key in the target is never overwritten.

    A customer whose key in the target matches the source is counted as skipped, 
    re-running a partial migration is safe. 
    A key that differs is reported as an error. 
    Customers in the target's deletion log are never imported, erasure survives migration.

    Raises:
        NotImplementedError: the target backend cannot import keys.

    Returns:
        MigrationResult with counts and any errors. Check .errors, failures are
        reported there, not raised.
    """
    result = MigrationResult()

    # Check whether the target can import keys.
    if type(target.backend).put_key is KeyBackend.put_key:
        raise NotImplementedError(
            f"{target.backend_name} does not support key import, nothing was migrated"
        )

    customer_ids = source.list_active_customers()
    result.total_keys = len(customer_ids)

    logger.info(
        "Migrating %d keys from %s to %s",
        result.total_keys,
        source.backend_name,
        target.backend_name,
    )

    forgotten_in_target = target.backend.filter_forgotten(customer_ids)

    for cid in customer_ids:
        try:
            if cid in forgotten_in_target:
                result.errors.append(
                    f"{cid}: erased in target backend - key not imported"
                )
                continue

            source_key = source.backend.get_key(cid)
            if source_key is None:
                result.errors.append(f"{cid}: key disappeared from source during migration")
                continue

            try:
                target.backend.put_key(
                    cid,
                    key_bytes=source_key.key_bytes,
                    created_at=source_key.created_at,
                )
                result.migrated += 1
            except KeyExistsError:
                existing = target.backend.get_key(cid)
                if existing is not None and existing.key_bytes == source_key.key_bytes:
                    # Already migrated, re-running is safe.
                    result.skipped += 1
                else:
                    result.errors.append(
                        f"{cid}: target already has a different key — not overwritten. "
                        "Resolve manually before retrying."
                    )

        except Exception as e:
            result.errors.append(f"{cid}: {e}")

    logger.info(
        "Migration complete: %d migrated, %d skipped, %d errors",
        result.migrated,
        result.skipped,
        len(result.errors),
    )
    if result.errors:
        logger.warning(
            "%d key(s) were not migrated and nothing was overwritten: %s",
            len(result.errors),
            "; ".join(result.errors[:10]),
        )

    return result
