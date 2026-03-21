"""
Tests for gdpr-officer v0.2.

Covers: DuckDB backend, encryption engine, DataFrame API, GDPR lifecycle,
key migration, and config parsing.
"""

import tempfile

import pytest

from gdpr_officer import GdprOfficerConfig, PiiEncryptor, migrate_keys
from gdpr_officer.backends.local import LocalKeystore
from gdpr_officer.encryptor import EncryptionEngine


# ── Helpers ──────────────────────────────────────────────────────────

PII = ["email", "phone", "address"]
CID = "customer_id"


def _officer(**overrides) -> PiiEncryptor:
    kwargs = {"key_backend": "local", "key_backend_config": {"db_path": ":memory:"}}
    kwargs.update(overrides)
    return PiiEncryptor(**kwargs)


def _row(customer_id: str = "cust-001") -> dict:
    return {
        "customer_id": customer_id,
        "email": "alice@example.com",
        "phone": "+31612345678",
        "address": "Keizersgracht 100, Amsterdam",
        "amount": 42.50,
    }


# ── DuckDB Backend ──────────────────────────────────────────────────


class TestLocalKeystore:
    def test_create_and_get(self):
        ks = LocalKeystore(db_path=":memory:")
        key = ks.create_key("c1")
        assert key.customer_id == "c1"
        assert len(key.key_bytes) == 32
        assert key.backend == "local"

        retrieved = ks.get_key("c1")
        assert retrieved is not None
        assert retrieved.key_bytes == key.key_bytes

    def test_idempotent_create(self):
        ks = LocalKeystore(db_path=":memory:")
        k1 = ks.create_key("c1")
        k2 = ks.create_key("c1")
        assert k1.key_bytes == k2.key_bytes

    def test_get_nonexistent(self):
        ks = LocalKeystore(db_path=":memory:")
        assert ks.get_key("nobody") is None

    def test_delete(self):
        ks = LocalKeystore(db_path=":memory:")
        ks.create_key("c1")
        record = ks.delete_key("c1", "GDPR request", "dpo@co.com")
        assert record.customer_id == "c1"
        assert ks.get_key("c1") is None

    def test_delete_nonexistent_raises(self):
        ks = LocalKeystore(db_path=":memory:")
        with pytest.raises(KeyError):
            ks.delete_key("nobody", "test", "test")

    def test_deletion_log(self):
        ks = LocalKeystore(db_path=":memory:")
        ks.create_key("c1")
        ks.create_key("c2")
        ks.delete_key("c1", "r1", "a")
        ks.delete_key("c2", "r2", "a")
        log = ks.get_deletion_log()
        assert len(log) == 2
        assert log[0].customer_id == "c1"

    def test_list_customers(self):
        ks = LocalKeystore(db_path=":memory:")
        ks.create_key("b")
        ks.create_key("a")
        ks.create_key("c")
        assert ks.list_customers() == ["a", "b", "c"]

    def test_batch_get_or_create(self):
        ks = LocalKeystore(db_path=":memory:")
        ks.create_key("existing")
        keys = ks.batch_get_or_create(["existing", "new-1", "new-2"])
        assert len(keys) == 3
        assert all(k.is_valid for k in keys.values())

    def test_file_persistence(self):
        import os

        with tempfile.NamedTemporaryFile(suffix=".duckdb", delete=False) as f:
            path = f.name
        os.unlink(path)  # DuckDB needs to create the file itself

        ks1 = LocalKeystore(db_path=path)
        ks1.create_key("persistent")
        ks1.close()

        ks2 = LocalKeystore(db_path=path)
        key = ks2.get_key("persistent")
        assert key is not None
        assert key.customer_id == "persistent"
        ks2.close()

    def test_export_parquet(self):
        with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as f:
            parquet_path = f.name

        ks = LocalKeystore(db_path=":memory:")
        ks.create_key("c1")
        ks.create_key("c2")
        ks.export_to_parquet(parquet_path)

        # Verify the parquet file is readable
        import duckdb

        conn = duckdb.connect()
        rows = conn.execute(f"SELECT * FROM '{parquet_path}'").fetchall()
        assert len(rows) == 2
        conn.close()


# ── Encryption Engine ────────────────────────────────────────────────


class TestEncryptionEngine:
    def _engine(self):
        ks = LocalKeystore(db_path=":memory:")
        config = GdprOfficerConfig()
        return EncryptionEngine(ks, config), ks

    def test_encrypt_decrypt_roundtrip(self):
        engine, ks = self._engine()
        key = ks.create_key("c1")
        enc = engine.encrypt_value("hello world", key)
        assert enc != "hello world"
        assert engine.decrypt_value(enc, key) == "hello world"

    def test_random_nonces(self):
        engine, ks = self._engine()
        key = ks.create_key("c1")
        e1 = engine.encrypt_value("same", key)
        e2 = engine.encrypt_value("same", key)
        assert e1 != e2

    def test_wrong_key_fails(self):
        engine, ks = self._engine()
        k1 = ks.create_key("c1")
        k2 = ks.create_key("c2")
        enc = engine.encrypt_value("secret", k1)
        with pytest.raises(Exception):
            engine.decrypt_value(enc, k2)


# ── Simple API ───────────────────────────────────────────────────────


class TestSimpleApi:
    def test_encrypt_decrypt_row(self):
        o = _officer()
        row = _row()
        enc = o.encrypt_row(row, customer_id=CID, pii=PII)
        assert enc["email"] != "alice@example.com"
        assert enc["amount"] == 42.50
        assert enc["customer_id"] == "cust-001"

        dec = o.decrypt_row(enc, customer_id=CID, pii=PII)
        assert dec["email"] == "alice@example.com"
        assert dec["phone"] == "+31612345678"

    def test_encrypt_rows_batch(self):
        o = _officer()
        rows = [_row(f"c{i}") for i in range(5)]
        enc = o.encrypt_rows(rows, customer_id=CID, pii=PII)
        assert len(enc) == 5
        assert all(r["email"] != "alice@example.com" for r in enc)

    def test_encrypt_df(self):
        pd = pytest.importorskip("pandas")
        o = _officer()
        df = pd.DataFrame([_row(f"c{i}") for i in range(3)])
        enc_df = o.encrypt_df(df, customer_id=CID, pii=PII)
        assert len(enc_df) == 3
        assert (enc_df["email"] != "alice@example.com").all()
        assert (enc_df["amount"] == 42.50).all()

    def test_decrypt_df(self):
        pd = pytest.importorskip("pandas")
        o = _officer()
        df = pd.DataFrame([_row(f"c{i}") for i in range(3)])
        enc_df = o.encrypt_df(df, customer_id=CID, pii=PII)
        dec_df = o.decrypt_df(enc_df, customer_id=CID, pii=PII)
        assert (dec_df["email"] == "alice@example.com").all()

    def test_decrypt_df_forgotten_customer(self):
        pd = pytest.importorskip("pandas")
        o = _officer()
        df = pd.DataFrame([_row("c0"), _row("c1"), _row("c2")])
        enc_df = o.encrypt_df(df, customer_id=CID, pii=PII)
        o.forget("c1", reason="GDPR", requested_by="dpo")
        dec_df = o.decrypt_df(enc_df, customer_id=CID, pii=PII)

        assert dec_df.loc[0, "email"] == "alice@example.com"
        assert dec_df.loc[2, "email"] == "alice@example.com"
        assert dec_df.loc[1, "email"] != "alice@example.com"  # Forgotten


# ── GDPR Lifecycle ───────────────────────────────────────────────────


class TestGdprLifecycle:
    def test_forget(self):
        o = _officer()
        o.encrypt_row(_row(), customer_id=CID, pii=PII)
        assert not o.is_forgotten("cust-001")

        record = o.forget("cust-001", reason="GDPR Art.17", requested_by="dpo@co.com")
        assert record.customer_id == "cust-001"
        assert o.is_forgotten("cust-001")

    def test_forget_blocks_decryption(self):
        o = _officer()
        enc = o.encrypt_row(_row(), customer_id=CID, pii=PII)
        o.forget("cust-001", reason="GDPR", requested_by="dpo")
        with pytest.raises(KeyError):
            o.decrypt_row(enc, customer_id=CID, pii=PII)

    def test_forget_is_permanent(self):
        o = _officer()
        enc = o.encrypt_row(_row(), customer_id=CID, pii=PII)
        o.forget("cust-001", reason="test", requested_by="test")

        # New key for same customer won't decrypt old data
        o.encrypt_row(_row(), customer_id=CID, pii=PII)
        dec = o.decrypt_row(enc, customer_id=CID, pii=PII)
        assert dec["email"] != "alice@example.com"

    def test_deletion_log(self):
        o = _officer()
        o.encrypt_row(_row("c1"), customer_id=CID, pii=PII)
        o.encrypt_row(_row("c2"), customer_id=CID, pii=PII)
        o.forget("c1", reason="r1", requested_by="a")
        o.forget("c2", reason="r2", requested_by="a")
        assert len(o.get_deletion_log()) == 2

    def test_list_active_customers(self):
        o = _officer()
        o.encrypt_row(_row("a"), customer_id=CID, pii=PII)
        o.encrypt_row(_row("b"), customer_id=CID, pii=PII)
        o.encrypt_row(_row("c"), customer_id=CID, pii=PII)
        assert o.list_active_customers() == ["a", "b", "c"]
        o.forget("b", reason="t", requested_by="t")
        assert o.list_active_customers() == ["a", "c"]


# ── Migration ────────────────────────────────────────────────────────


class TestMigration:
    def test_migrate_local_to_local(self):
        src = _officer()
        tgt = _officer()

        # Encrypt some rows in source (creates keys)
        row = _row("c1")
        enc = src.encrypt_row(row, customer_id=CID, pii=PII)

        # Migrate keys
        result = migrate_keys(source=src, target=tgt)
        assert result.total_keys == 1
        assert result.migrated == 1
        assert result.skipped == 0

        # Target can now decrypt data encrypted by source
        dec = tgt.decrypt_row(enc, customer_id=CID, pii=PII)
        assert dec["email"] == "alice@example.com"

    def test_migrate_skips_existing(self):
        src = _officer()
        tgt = _officer()

        src.encrypt_row(_row("c1"), customer_id=CID, pii=PII)
        tgt.encrypt_row(_row("c1"), customer_id=CID, pii=PII)

        result = migrate_keys(source=src, target=tgt)
        assert result.skipped == 1
        assert result.migrated == 0

    def test_migrate_multiple_keys(self):
        src = _officer()
        tgt = _officer()

        for i in range(5):
            src.encrypt_row(_row(f"c{i}"), customer_id=CID, pii=PII)

        result = migrate_keys(source=src, target=tgt)
        assert result.total_keys == 5
        assert result.migrated == 5


# ── Config ───────────────────────────────────────────────────────────


class TestConfig:
    def test_from_dict(self):
        config = GdprOfficerConfig.from_dict({
            "customer_identifier": "cid",
            "key_backend": "local",
            "sources": [{"name": "t", "customer_id_column": "cid", "pii_columns": ["email"]}],
        })
        assert config.customer_identifier == "cid"

    def test_customer_id_in_pii_raises(self):
        with pytest.raises(ValueError, match="cannot be a pii_column"):
            GdprOfficerConfig.from_dict({
                "customer_identifier": "cid",
                "key_backend": "local",
                "sources": [{"name": "t", "customer_id_column": "cid", "pii_columns": ["cid"]}],
            })

    def test_missing_config_file(self):
        with pytest.raises(FileNotFoundError):
            GdprOfficerConfig.from_yaml("/nonexistent.yaml")

    def test_named_source_api(self):
        enc = PiiEncryptor.from_dict({
            "customer_identifier": "customer_id",
            "key_backend": "local",
            "key_backend_config": {"db_path": ":memory:"},
            "sources": [
                {"name": "users", "customer_id_column": "customer_id", "pii_columns": PII}
            ],
        })
        row = _row()
        encrypted = enc.encrypt(row, source="users")
        assert encrypted["email"] != row["email"]
        decrypted = enc.decrypt(encrypted, source="users")
        assert decrypted["email"] == row["email"]

    def test_invalid_source_raises(self):
        enc = PiiEncryptor.from_dict({
            "customer_identifier": "customer_id",
            "key_backend": "local",
            "key_backend_config": {"db_path": ":memory:"},
            "sources": [
                {"name": "users", "customer_id_column": "customer_id", "pii_columns": PII}
            ],
        })
        with pytest.raises(KeyError, match="not found"):
            enc.encrypt(_row(), source="nonexistent")
