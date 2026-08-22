"""
Google Cloud Firestore key backend.

Stores per-customer encryption keys in Firestore, separated from
the data warehouse.

Setup:
    1. Create a Firestore database: gcloud firestore databases create --location=<region>
    2. Grant pipeline service account: roles/datastore.user
    3. Grant DPO / compliance role: roles/datastore.user
    4. Analysts who query from the warehouse should not have access to the key store

Requires: pip install gdpr-officer[gcp]
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

try:
    from google.api_core.exceptions import AlreadyExists
    from google.cloud import firestore
    from google.cloud.firestore_v1 import FieldFilter

    HAS_FIRESTORE = True
except ImportError:
    HAS_FIRESTORE = False

from gdpr_officer.exceptions import KeyExistsError
from gdpr_officer.key_backend import (
    CustomerKey,
    DeletionRecord,
    KeyBackend,
    register_backend,
)

# Default collection names
_KEYS_COLLECTION = "gdpr_officer_keys"
_DELETION_LOG_COLLECTION = "gdpr_officer_deletion_log"


@register_backend("gcp_firestore")
class FirestoreKeystore(KeyBackend):
    """
    Firestore-backed key management for production use.

    Keys are stored as documents in a Firestore collection, each containing
    the raw AES-256 key bytes. The deletion audit log is a separate collection
    in the same database.

    Args:
        project: GCP project ID.
        database: Firestore database name. Default "(default)".
        keys_collection: Collection name for keys. Default "gdpr_officer_keys".
        deletion_log_collection: Collection for audit log. Default "gdpr_officer_deletion_log".
    """

    def __init__(
        self,
        project: str,
        database: str = "(default)",
        keys_collection: str = _KEYS_COLLECTION,
        deletion_log_collection: str = _DELETION_LOG_COLLECTION,
    ):
        if not HAS_FIRESTORE:
            raise ImportError(
                "Firestore dependencies not installed. "
                "Install with: pip install gdpr-officer[gcp]"
            )

        self._client = firestore.Client(project=project, database=database)
        self._keys = self._client.collection(keys_collection)
        self._deletion_log = self._client.collection(deletion_log_collection)

    def get_key(self, customer_id: str) -> CustomerKey | None:
        data = self._keys.document(customer_id).get().to_dict()

        if data is None:
            return None

        return CustomerKey(
            customer_id=customer_id,
            key_bytes=data["key_bytes"],
            created_at=datetime.fromisoformat(data["created_at"]),
            backend="gcp_firestore",
        )

    def create_key(self, customer_id: str) -> CustomerKey:
        existing = self.get_key(customer_id)
        if existing is not None:
            return existing

        key_bytes = os.urandom(32)
        now = datetime.now(timezone.utc)

        try:
            # create() fails if a key exists due to a concurrent run.
            self._keys.document(customer_id).create({
                "key_bytes": key_bytes,
                "created_at": now.isoformat(),
            })
        except AlreadyExists:
            winner = self.get_key(customer_id)
            if winner is None:
                raise
            return winner

        return CustomerKey(
            customer_id=customer_id,
            key_bytes=key_bytes,
            created_at=now,
            backend="gcp_firestore",
        )

    def put_key(self, customer_id: str, key_bytes: bytes, created_at: datetime) -> None:
        """Write an existing key as is. Prevents overwrite of existing keys."""
        # create() fails if a key already exists.
        try:
            self._keys.document(customer_id).create({
                "key_bytes": key_bytes,
                "created_at": created_at.isoformat(),
            })
        except AlreadyExists as e:
            raise KeyExistsError(customer_id) from e

    def delete_key(self, customer_id: str, reason: str, requested_by: str) -> DeletionRecord:
        now = datetime.now(timezone.utc)

        doc = self._keys.document(customer_id).get()
        if not doc.exists:
            raise KeyError(
                f"No active key for customer '{customer_id}'. "
                "May have already been deleted."
            )

        # Delete key and log in a batch (atomic)
        batch = self._client.batch()
        batch.delete(self._keys.document(customer_id))
        batch.set(self._deletion_log.document(), {
            "customer_id": customer_id,
            "deleted_at": now.isoformat(),
            "reason": reason,
            "requested_by": requested_by,
        })
        batch.commit()

        return DeletionRecord(
            customer_id=customer_id,
            deleted_at=now,
            reason=reason,
            requested_by=requested_by,
        )

    def list_customers(self) -> list[str]:
        docs = self._keys.stream()
        return sorted(doc.id for doc in docs)

    def get_deletion_log(self) -> list[DeletionRecord]:
        docs = self._deletion_log.order_by("deleted_at").stream()
        records = []
        for doc in docs:
            data = doc.to_dict()
            if data is None:
                continue
            records.append(DeletionRecord(
                customer_id=data["customer_id"],
                deleted_at=datetime.fromisoformat(data["deleted_at"]),
                reason=data["reason"],
                requested_by=data["requested_by"],
            ))
        return records

    def filter_forgotten(self, customer_ids: list[str]) -> set[str]:
        """Which of these customers appear in the deletion log."""
        if not customer_ids:
            return set()

        found: set[str] = set()
        for start in range(0, len(customer_ids), 30):
            chunk = customer_ids[start:start + 30]
            query = self._deletion_log.where(
                filter=FieldFilter("customer_id", "in", chunk)
            )
            for doc in query.stream():
                data = doc.to_dict()
                if data is not None:
                    found.add(data["customer_id"])
        return found

    def batch_get_or_create(self, customer_ids: list[str]) -> dict[str, CustomerKey]:
        """Batch key retrieval with creation for new customers."""
        if not customer_ids:
            return {}

        results = {}
        now = datetime.now(timezone.utc)

        # Firestore get_all for batch reads
        doc_refs = [self._keys.document(cid) for cid in customer_ids]
        docs = self._client.get_all(doc_refs)

        existing_ids = set()
        for doc in docs:
            data = doc.to_dict()
            if data is None:
                continue
            existing_ids.add(doc.id)
            results[doc.id] = CustomerKey(
                customer_id=doc.id,
                key_bytes=data["key_bytes"],
                created_at=datetime.fromisoformat(data["created_at"]),
                backend="gcp_firestore",
            )

        # If any key in a batch already exists, each key is resolved individually.
        new_ids = [cid for cid in customer_ids if cid not in existing_ids]
        for start in range(0, len(new_ids), 499):
            chunk = new_ids[start:start + 499]
            fresh = {cid: os.urandom(32) for cid in chunk}
            batch = self._client.batch()
            for cid in chunk:
                batch.create(self._keys.document(cid), {
                    "key_bytes": fresh[cid],
                    "created_at": now.isoformat(),
                })
            try:
                batch.commit()
            except AlreadyExists:
                for cid in chunk:
                    results[cid] = self.create_key(cid)
                continue
            for cid in chunk:
                results[cid] = CustomerKey(
                    customer_id=cid,
                    key_bytes=fresh[cid],
                    created_at=now,
                    backend="gcp_firestore",
                )

        return results
