"""
Local key backend using DuckDB.

Stores encryption keys in a local DuckDB file. Intended for development
and testing. For production, use a cloud backend to separate keys from
the data warehouse.

Keys can be migrated to a cloud backend using migrate_keys().
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional

import duckdb

from gdpr_officer.key_backend import (
    CustomerKey,
    DeletionRecord,
    KeyBackend,
    register_backend,
)

logger = logging.getLogger("gdpr_officer")

_SCHEMA_SQL = [
    """
    CREATE TABLE IF NOT EXISTS customer_keys (
        customer_id VARCHAR PRIMARY KEY,
        key_bytes BLOB NOT NULL,
        created_at VARCHAR NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS deletion_log (
        id INTEGER DEFAULT nextval('deletion_log_seq'),
        customer_id VARCHAR NOT NULL,
        deleted_at VARCHAR NOT NULL,
        reason VARCHAR NOT NULL,
        requested_by VARCHAR NOT NULL
    )
    """,
]

_WARNING = (
    "gdpr-officer is using LOCAL key storage at '%s'. "
    "This is not recommended for production. Keys should be stored outside "
    "the data platform. Use a cloud backend for production."
)


@register_backend("local")
class LocalKeystore(KeyBackend):
    """
    DuckDB-backed key management for development and testing.

    Args:
        db_path: Path to the DuckDB database file.
                 Defaults to 'gdpr_officer_keys.duckdb'.
                 Use ':memory:' for in-memory (ephemeral, testing only).
    """

    def __init__(self, db_path: str = "gdpr_officer_keys.duckdb"):
        self._db_path = db_path
        self._is_memory = db_path == ":memory:"
        self._conn = duckdb.connect(db_path)
        self._init_db()

        if not self._is_memory:
            logger.warning(_WARNING, db_path)

    def _init_db(self):
        # Create sequence for deletion log IDs (ignore if exists)
        try:
            self._conn.execute("CREATE SEQUENCE deletion_log_seq START 1")
        except duckdb.CatalogException:
            pass
        for sql in _SCHEMA_SQL:
            self._conn.execute(sql)

    def get_key(self, customer_id: str) -> Optional[CustomerKey]:
        result = self._conn.execute(
            "SELECT key_bytes, created_at FROM customer_keys WHERE customer_id = ?",
            [customer_id],
        ).fetchone()

        if result is None:
            return None

        return CustomerKey(
            customer_id=customer_id,
            key_bytes=bytes(result[0]),
            created_at=datetime.fromisoformat(result[1]),
            backend="local",
        )

    def create_key(self, customer_id: str) -> CustomerKey:
        existing = self.get_key(customer_id)
        if existing is not None:
            return existing

        key_bytes = os.urandom(32)
        now = datetime.now(timezone.utc)

        self._conn.execute(
            "INSERT INTO customer_keys (customer_id, key_bytes, created_at) VALUES (?, ?, ?)",
            [customer_id, key_bytes, now.isoformat()],
        )

        return CustomerKey(
            customer_id=customer_id,
            key_bytes=key_bytes,
            created_at=now,
            backend="local",
        )

    def delete_key(self, customer_id: str, reason: str, requested_by: str) -> DeletionRecord:
        now = datetime.now(timezone.utc)

        existing = self._conn.execute(
            "SELECT 1 FROM customer_keys WHERE customer_id = ?",
            [customer_id],
        ).fetchone()

        if existing is None:
            raise KeyError(
                f"No active key for customer '{customer_id}'. "
                "May have already been deleted."
            )

        self._conn.execute(
            "DELETE FROM customer_keys WHERE customer_id = ?",
            [customer_id],
        )
        self._conn.execute(
            "INSERT INTO deletion_log (customer_id, deleted_at, reason, requested_by) "
            "VALUES (?, ?, ?, ?)",
            [customer_id, now.isoformat(), reason, requested_by],
        )

        return DeletionRecord(
            customer_id=customer_id,
            deleted_at=now,
            reason=reason,
            requested_by=requested_by,
        )

    def list_customers(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT customer_id FROM customer_keys ORDER BY customer_id"
        ).fetchall()
        return [r[0] for r in rows]

    def get_deletion_log(self) -> list[DeletionRecord]:
        rows = self._conn.execute(
            "SELECT customer_id, deleted_at, reason, requested_by "
            "FROM deletion_log ORDER BY deleted_at"
        ).fetchall()
        return [
            DeletionRecord(
                customer_id=r[0],
                deleted_at=datetime.fromisoformat(r[1]),
                reason=r[2],
                requested_by=r[3],
            )
            for r in rows
        ]

    def batch_get_or_create(self, customer_ids: list[str]) -> dict[str, CustomerKey]:
        """Optimised batch operation."""
        results = {}
        now = datetime.now(timezone.utc)

        # Fetch all existing keys
        placeholders = ",".join("?" for _ in customer_ids)
        rows = self._conn.execute(
            f"SELECT customer_id, key_bytes, created_at FROM customer_keys "
            f"WHERE customer_id IN ({placeholders})",
            customer_ids,
        ).fetchall()

        existing = {
            r[0]: CustomerKey(
                customer_id=r[0],
                key_bytes=bytes(r[1]),
                created_at=datetime.fromisoformat(r[2]),
                backend="local",
            )
            for r in rows
        }

        # Create keys for new customers
        new_records = []
        for cid in customer_ids:
            if cid in existing:
                results[cid] = existing[cid]
            else:
                key_bytes = os.urandom(32)
                new_records.append((cid, key_bytes, now.isoformat()))
                results[cid] = CustomerKey(
                    customer_id=cid,
                    key_bytes=key_bytes,
                    created_at=now,
                    backend="local",
                )

        if new_records:
            self._conn.executemany(
                "INSERT OR IGNORE INTO customer_keys (customer_id, key_bytes, created_at) "
                "VALUES (?, ?, ?)",
                new_records,
            )

        return results

    def export_to_parquet(self, path: str = "gdpr_officer_keys_backup.parquet"):
        """
        Export all keys to a Parquet file for backup or migration.

        WARNING: The exported file contains raw encryption keys.
        Handle with the same security as the DuckDB file itself.
        """
        self._conn.execute(
            f"COPY customer_keys TO '{path}' (FORMAT PARQUET)"
        )
        logger.info("Exported %d keys to %s", len(self.list_customers()), path)

    def close(self):
        """Close the DuckDB connection."""
        self._conn.close()
