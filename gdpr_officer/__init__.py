"""
gdpr-officer: PII encryption and GDPR-compliant data erasure for data platforms.
Delete a key, forget a customer.
"""

__version__ = "0.4.0"

from gdpr_officer.api import PiiEncryptor
from gdpr_officer.config import GdprOfficerConfig
from gdpr_officer.exceptions import ForgottenCustomerError, GdprOfficerError
from gdpr_officer.generalise import age_group, mapping, numeric_range, truncate
from gdpr_officer.migrate import migrate_keys

__all__ = [
    "PiiEncryptor",
    "GdprOfficerConfig",
    "migrate_keys",
    "age_group",
    "mapping",
    "numeric_range",
    "truncate",
    "ForgottenCustomerError",
    "GdprOfficerError",
]
