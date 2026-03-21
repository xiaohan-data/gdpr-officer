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
from typing import Optional

try:
    from google.cloud import firestore

    HAS_FIRESTORE = True
except ImportError:
    HAS_FIRESTORE = False

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

    def get_key(self, customer_id: str) -> Optional[CustomerKey]:
        doc = self._keys.document(customer_id).get()

        if not doc.exists:
            return None

        data = doc.to_dict()
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

        self._keys.document(customer_id).set({
            "key_bytes": key_bytes,
            "created_at": now.isoformat(),
        })

        return CustomerKey(
            customer_id=customer_id,
            key_bytes=key_bytes,
            created_at=now,
            backend="gcp_firestore",
        )

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
        return [
            DeletionRecord(
                customer_id=doc.to_dict()["customer_id"],
                deleted_at=datetime.fromisoformat(doc.to_dict()["deleted_at"]),
                reason=doc.to_dict()["reason"],
                requested_by=doc.to_dict()["requested_by"],
            )
            for doc in docs
        ]

    def batch_get_or_create(self, customer_ids: list[str]) -> dict[str, CustomerKey]:
        """Batch key retrieval with creation for new customers."""
        results = {}
        now = datetime.now(timezone.utc)

        # Firestore get_all for batch reads
        doc_refs = [self._keys.document(cid) for cid in customer_ids]
        docs = self._client.get_all(doc_refs)

        existing_ids = set()
        for doc in docs:
            if doc.exists:
                data = doc.to_dict()
                existing_ids.add(doc.id)
                results[doc.id] = CustomerKey(
                    customer_id=doc.id,
                    key_bytes=data["key_bytes"],
                    created_at=datetime.fromisoformat(data["created_at"]),
                    backend="gcp_firestore",
                )

        # Create keys for new customers in a batch write
        batch = self._client.batch()
        batch_count = 0
        for cid in customer_ids:
            if cid not in existing_ids:
                key_bytes = os.urandom(32)
                batch.set(self._keys.document(cid), {
                    "key_bytes": key_bytes,
                    "created_at": now.isoformat(),
                })
                results[cid] = CustomerKey(
                    customer_id=cid,
                    key_bytes=key_bytes,
                    created_at=now,
                    backend="gcp_firestore",
                )
                batch_count += 1

                # Firestore batches are limited to 500 operations
                if batch_count >= 499:
                    batch.commit()
                    batch = self._client.batch()
                    batch_count = 0

        if batch_count > 0:
            batch.commit()

        return results
