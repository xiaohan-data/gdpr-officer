"""Exceptions raised by gdpr-officer."""

from __future__ import annotations


class GdprOfficerError(Exception):
    """Base class for all gdpr-officer errors."""


class ForgottenCustomerError(GdprOfficerError):
    """
    Raised when encryption is attempted for a customer who was forgotten
    (their key was deleted via forget()). The offending customer IDs are
    available on .customer_ids.
    """

    def __init__(self, customer_ids: list[str]):
        self.customer_ids = list(customer_ids)
        preview = ", ".join(self.customer_ids[:5])
        if len(self.customer_ids) > 5:
            preview += f", … (+{len(self.customer_ids) - 5} more)"
        super().__init__(
            f"Refusing to encrypt erased customer(s): {preview}. "
            "Pass on_forgotten='skip' to drop their rows, or fix the "
            "upstream source so they stop arriving."
        )


class KeyExistsError(GdprOfficerError):
    """
    Raised when writing a key for a customer who already has a key. 
    Prevents overwrite of existing keys.
    """

    def __init__(self, customer_id: str):
        self.customer_id = customer_id
        super().__init__(
            f"Customer '{customer_id}' already has a key. Keys are never overwritten. "
            "Delete the existing key first if replacing it is genuinely intended."
        )
