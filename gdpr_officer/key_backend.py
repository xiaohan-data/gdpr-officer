"""
Abstract interface for key management backends.

Every backend must implement these methods. 

Keys are stored outside the data warehouse to maintain security separation.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class CustomerKey:
    """A single customer's encryption key with metadata."""

    customer_id: str
    key_bytes: bytes
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    backend: str = ""

    @property
    def is_valid(self) -> bool:
        return len(self.key_bytes) > 0


@dataclass(frozen=True)
class DeletionRecord:
    """Audit record for a key deletion (GDPR erasure) event."""

    customer_id: str
    deleted_at: datetime
    reason: str
    requested_by: str


class KeyBackend(abc.ABC):
    """
    Abstract interface for per-customer encryption key management.

    Implementations must guarantee:
    - One key per customer_id (idempotent creation).
    - Key deletion is permanent and irreversible.
    - Deletion is logged for audit compliance.
    - Keys are stored outside the data warehouse.
    """

    @abc.abstractmethod
    def get_key(self, customer_id: str) -> Optional[CustomerKey]:
        """Retrieve the encryption key for a customer. Returns None if not found."""
        ...

    @abc.abstractmethod
    def create_key(self, customer_id: str) -> CustomerKey:
        """Create a new key for a customer. If one exists, return it (idempotent)."""
        ...

    @abc.abstractmethod
    def delete_key(self, customer_id: str, reason: str, requested_by: str) -> DeletionRecord:
        """
        Permanently delete a customer's key and log the deletion.
        This is the GDPR erasure action — 
        all PII encrypted with this key becomes permanently unrecoverable.
        """
        ...

    @abc.abstractmethod
    def list_customers(self) -> list[str]:
        """List all customer IDs with active keys."""
        ...

    @abc.abstractmethod
    def get_deletion_log(self) -> list[DeletionRecord]:
        """Return the full audit log of key deletions."""
        ...

    def get_or_create_key(self, customer_id: str) -> CustomerKey:
        """Get existing key or create a new one."""
        key = self.get_key(customer_id)
        if key is not None:
            return key
        return self.create_key(customer_id)

    def batch_get_or_create(self, customer_ids: list[str]) -> dict[str, CustomerKey]:
        """Batch key retrieval. Backends can override for optimised bulk operations."""
        return {cid: self.get_or_create_key(cid) for cid in customer_ids}


# Backend registry
BACKENDS: dict[str, type[KeyBackend]] = {}


def register_backend(name: str):
    """Decorator to register a key backend implementation."""

    def decorator(cls: type[KeyBackend]):
        BACKENDS[name] = cls
        return cls

    return decorator


def get_backend(name: str, **kwargs) -> KeyBackend:
    """Instantiate a registered backend by name."""
    if name not in BACKENDS:
        available = ", ".join(BACKENDS.keys()) or "(none)"
        raise ValueError(f"Unknown key backend: '{name}'. Available: {available}")
    return BACKENDS[name](**kwargs)
