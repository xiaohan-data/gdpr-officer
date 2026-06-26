"""
Regression tests for the forgotten-customer-on-encryption guard.

Forgetting a customer deletes their key. If a forgotten customer_id data shows up again in a
later run (such as re-ingested data), the library either refuses or skips them.
"""

import random

import pytest

from gdpr_officer import ForgottenCustomerError, PiiEncryptor
from gdpr_officer.backends.local import LocalKeystore
from gdpr_officer.config import GdprOfficerConfig
from gdpr_officer.encryptor import EncryptionEngine

PII = ["email", "phone"]
CID = "customer_id"


def _officer(**overrides) -> PiiEncryptor:
    kwargs = {"key_backend": "local", "key_backend_config": {"db_path": ":memory:"}}
    kwargs.update(overrides)
    return PiiEncryptor(**kwargs)


def _row(customer_id="c1"):
    return {
        "customer_id": customer_id,
        "email": "alice@example.com",
        "phone": "+31612345678",
        "amount": 42.50,
    }


# ── Forgotten-customer guard on encryption ───────────────────────────


class TestForgottenCustomerGuard:
    def test_error_is_the_default(self):
        o = _officer()
        o.encrypt_row(_row("c1"), customer_id=CID, pii=PII)
        o.forget("c1", reason="GDPR", requested_by="dpo")
        with pytest.raises(ForgottenCustomerError):
            o.encrypt_row(_row("c1"), customer_id=CID, pii=PII)

    def test_error_mode_carries_ids(self):
        o = _officer(on_forgotten="error")
        o.encrypt_rows([_row("a"), _row("b")], customer_id=CID, pii=PII)
        o.forget("b", reason="GDPR", requested_by="dpo")
        with pytest.raises(ForgottenCustomerError) as exc:
            o.encrypt_rows([_row("a"), _row("b")], customer_id=CID, pii=PII)
        assert "b" in exc.value.customer_ids

    def test_skip_mode_drops_only_forgotten_rows(self):
        o = _officer(on_forgotten="skip")
        o.encrypt_rows([_row("a"), _row("b"), _row("c")], customer_id=CID, pii=PII)
        o.forget("b", reason="GDPR", requested_by="dpo")
        out = o.encrypt_rows([_row("a"), _row("b"), _row("c")], customer_id=CID, pii=PII)
        assert len(out) == 2
        assert {r["customer_id"] for r in out} == {"a", "c"}

    def test_skip_mode_does_not_recreate_key(self):
        o = _officer(on_forgotten="skip")
        o.encrypt_row(_row("c1"), customer_id=CID, pii=PII)
        o.forget("c1", reason="GDPR", requested_by="dpo")
        o.encrypt_rows([_row("c1")], customer_id=CID, pii=PII)  # skipped
        assert o.is_forgotten("c1")  # still forgotten, no new key
        assert "c1" not in o.list_active_customers()

    def test_old_ciphertext_stays_shredded(self):
        # The existing permanence guarantee must still hold.
        o = _officer(on_forgotten="skip")
        enc = o.encrypt_row(_row("c1"), customer_id=CID, pii=PII)
        o.forget("c1", reason="GDPR", requested_by="dpo")
        with pytest.raises(KeyError):
            o.decrypt_row(enc, customer_id=CID, pii=PII)

    def test_invalid_on_forgotten_rejected(self):
        with pytest.raises(ValueError):
            _officer(on_forgotten="nonsense")


class TestEncryptDfForgotten:
    def test_df_error_mode_raises(self):
        pd = pytest.importorskip("pandas")
        o = _officer()
        df = pd.DataFrame([_row("a"), _row("b")])
        o.encrypt_df(df, customer_id=CID, pii=PII)
        o.forget("b", reason="GDPR", requested_by="dpo")
        with pytest.raises(ForgottenCustomerError):
            o.encrypt_df(df, customer_id=CID, pii=PII)

    def test_df_skip_mode_drops_rows(self):
        pd = pytest.importorskip("pandas")
        o = _officer(on_forgotten="skip")
        df = pd.DataFrame([_row("a"), _row("b"), _row("c")])
        o.encrypt_df(df, customer_id=CID, pii=PII)
        o.forget("b", reason="GDPR", requested_by="dpo")
        out = o.encrypt_df(df, customer_id=CID, pii=PII)
        assert len(out) == 2


# ── is_forgotten / filter_forgotten ──────────────────────────────────


class TestIsForgotten:
    def test_erased_customer_is_forgotten(self):
        o = _officer()
        o.encrypt_row(_row("c1"), customer_id=CID, pii=PII)
        o.forget("c1", reason="GDPR", requested_by="dpo")
        assert o.is_forgotten("c1") is True

    def test_never_seen_customer_is_not_forgotten(self):
        o = _officer()
        assert o.is_forgotten("ghost") is False

    def test_active_customer_is_not_forgotten(self):
        o = _officer()
        o.encrypt_row(_row("c1"), customer_id=CID, pii=PII)
        assert o.is_forgotten("c1") is False

    def test_key_present_and_in_log_is_not_forgotten(self):
        # A key exists and a deletion record exists: still decryptable,
        # so not forgotten.
        o = _officer()
        ks = o._backend
        ks.create_key("c1")
        ks.delete_key("c1", "GDPR", "dpo")  # state: no key, in log
        ks.create_key("c1")                  # key written back -> key + log entry
        assert o.is_forgotten("c1") is False


class TestFilterForgottenBackend:
    def test_returns_only_erased(self):
        ks = LocalKeystore(db_path=":memory:")
        ks.create_key("a")
        ks.create_key("b")
        ks.delete_key("a", "GDPR", "dpo")
        assert ks.filter_forgotten(["a", "b", "ghost"]) == {"a"}

    def test_empty_input(self):
        ks = LocalKeystore(db_path=":memory:")
        assert ks.filter_forgotten([]) == set()


# ── Crypto round-trip fuzz (no new dependency) ───────────────────────


class TestCryptoRoundtripFuzz:
    def test_arbitrary_unicode_roundtrips(self):
        ks = LocalKeystore(db_path=":memory:")
        engine = EncryptionEngine(ks, GdprOfficerConfig())
        key = ks.create_key("c1")
        rng = random.Random(1234)
        for _ in range(200):
            length = rng.randint(0, 64)
            text = "".join(chr(rng.randint(1, 0x2FFF)) for _ in range(length))
            enc = engine.encrypt_value(text, key)
            assert engine.decrypt_value(enc, key) == text
