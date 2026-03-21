"""Key management backend implementations."""

from gdpr_officer.backends.local import LocalKeystore

__all__ = ["LocalKeystore"]

try:
    from gdpr_officer.backends.gcp_firestore import FirestoreKeystore  # noqa: F401

    __all__.append("FirestoreKeystore")
except ImportError:
    pass
