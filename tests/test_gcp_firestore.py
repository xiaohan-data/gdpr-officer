"""
Tests for the Firestore key backend.

These run against an in-memory fake of the Firestore client, 
no credentials or emulator needed. 

The fake models the behaviour the backend relies on: 
create() refuse to overwrite, 
write batches apply nothing when any create in the batch conflicts, 
get_all, and 'in' queries on the deletion log.
"""

import uuid
from datetime import datetime, timezone

import pandas as pd
import pytest

import gdpr_officer.backends.gcp_firestore as firestore_backend
from gdpr_officer import ForgottenCustomerError, PiiEncryptor
from gdpr_officer.backends.gcp_firestore import FirestoreKeystore
from gdpr_officer.exceptions import KeyExistsError

_exceptions = pytest.importorskip("google.api_core.exceptions")
AlreadyExists = _exceptions.AlreadyExists


# ── In-memory fake Firestore client ──────────────────────────────────

class FakeSnapshot:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = data

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return dict(self._data) if self._data is not None else None


class FakeDocumentReference:
    def __init__(self, store, doc_id, client):
        self._store = store
        self.id = doc_id
        self._client = client

    def get(self):
        return FakeSnapshot(self.id, self._store.get(self.id))

    def create(self, data):
        self._client.counters["doc_creates"] += 1
        if self.id in self._store:
            raise AlreadyExists(f"document {self.id} already exists")
        self._store[self.id] = dict(data)

    def set(self, data):
        self._store[self.id] = dict(data)

    def delete(self):
        self._store.pop(self.id, None)


class FakeQuery:
    def __init__(self, store):
        self._store = store
        self._in_filter = None
        self._order_field = None

    def where(self, filter):
        op = getattr(filter, "op_string", None)
        assert op == "in", f"fake only models 'in' queries, got {op!r}"
        q = FakeQuery(self._store)
        q._in_filter = (getattr(filter, "field_path", None), list(filter.value))
        return q

    def order_by(self, field):
        q = FakeQuery(self._store)
        q._in_filter = self._in_filter
        q._order_field = field
        return q

    def stream(self):
        items = list(self._store.items())
        if self._in_filter is not None:
            field, values = self._in_filter
            items = [(i, d) for i, d in items if d.get(field) in values]
        if self._order_field is not None:
            items.sort(key=lambda kv: kv[1][self._order_field])
        return (FakeSnapshot(i, d) for i, d in items)


class FakeCollection(FakeQuery):
    def __init__(self, store, client):
        super().__init__(store)
        self._client = client

    def document(self, doc_id=None):
        return FakeDocumentReference(self._store, doc_id or uuid.uuid4().hex, self._client)


class FakeBatch:
    def __init__(self, client):
        self._client = client
        self._creates = []
        self._sets = []
        self._deletes = []

    def create(self, ref, data):
        self._creates.append((ref, dict(data)))

    def set(self, ref, data):
        self._sets.append((ref, dict(data)))

    def delete(self, ref):
        self._deletes.append(ref)

    def commit(self):
        self._client.counters["batch_commits"] += 1
        hook = self._client.before_commit
        if hook is not None:
            self._client.before_commit = None
            hook()
        # A batch is atomic: one create conflict fails the whole commit
        # and none of the queued writes apply.
        for ref, _ in self._creates:
            if ref.id in ref._store:
                raise AlreadyExists(f"document {ref.id} already exists")
        for ref, data in self._creates:
            ref._store[ref.id] = data
        for ref, data in self._sets:
            ref._store[ref.id] = data
        for ref in self._deletes:
            ref._store.pop(ref.id, None)


class FakeClient:
    def __init__(self, project, database="(default)"):
        self.project = project
        self.database = database
        self._collections = {}
        self.counters = {"doc_creates": 0, "batch_commits": 0}
        self.before_commit = None

    def collection(self, name):
        return FakeCollection(self._collections.setdefault(name, {}), self)

    def get_all(self, refs):
        return (ref.get() for ref in refs)

    def batch(self):
        return FakeBatch(self)

    def store(self, name):
        return self._collections.setdefault(name, {})


@pytest.fixture
def backend(monkeypatch):
    holder = {}

    def factory(project, database="(default)"):
        holder["client"] = FakeClient(project, database)
        return holder["client"]

    monkeypatch.setattr(firestore_backend.firestore, "Client", factory)
    return FirestoreKeystore(project="test-project"), holder["client"]


# ── create_key ───────────────────────────────────────────────────────

def test_create_key_stores_and_returns_key(backend):
    keystore, client = backend
    key = keystore.create_key("c-1")
    assert len(key.key_bytes) == 32
    assert key.backend == "gcp_firestore"
    assert "c-1" in client.store("gdpr_officer_keys")


def test_create_key_is_idempotent(backend):
    keystore, client = backend
    first = keystore.create_key("c-1")
    second = keystore.create_key("c-1")
    assert second.key_bytes == first.key_bytes
    assert len(client.store("gdpr_officer_keys")) == 1


def test_create_key_race_keeps_the_first_key(backend):
    # Another concurrent run writes a key between this call's read and its write. 
    # The key already in the store wins.
    keystore, client = backend
    winner = b"w" * 32
    original_create = firestore_backend.FirestoreKeystore.get_key

    def interloper(self, customer_id):
        result = original_create(self, customer_id)
        if result is None:
            client.store("gdpr_officer_keys")[customer_id] = {
                "key_bytes": winner,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        return result

    firestore_backend.FirestoreKeystore.get_key = interloper
    try:
        key = keystore.create_key("c-1")
    finally:
        firestore_backend.FirestoreKeystore.get_key = original_create

    assert key.key_bytes == winner
    assert client.store("gdpr_officer_keys")["c-1"]["key_bytes"] == winner


# ── put_key ──────────────────────────────────────────────────────────

def test_put_key_writes_verbatim(backend):
    keystore, _ = backend
    created_at = datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc)
    keystore.put_key("c-1", b"k" * 32, created_at)
    stored = keystore.get_key("c-1")
    assert stored.key_bytes == b"k" * 32
    assert stored.created_at == created_at


def test_put_key_never_overwrites(backend):
    keystore, _ = backend
    keystore.create_key("c-1")
    with pytest.raises(KeyExistsError):
        keystore.put_key("c-1", b"k" * 32, datetime.now(timezone.utc))


# ── batch_get_or_create ──────────────────────────────────────────────

def test_batch_mixes_existing_and_new(backend):
    keystore, client = backend
    existing = keystore.create_key("a")
    result = keystore.batch_get_or_create(["a", "b", "c"])
    assert set(result) == {"a", "b", "c"}
    assert result["a"].key_bytes == existing.key_bytes
    assert len(client.store("gdpr_officer_keys")) == 3


def test_batch_empty_input_touches_nothing(backend):
    keystore, client = backend
    assert keystore.batch_get_or_create([]) == {}
    assert client.counters == {"doc_creates": 0, "batch_commits": 0}


def test_batch_uses_chunked_batched_writes(backend):
    keystore, client = backend
    result = keystore.batch_get_or_create([f"c-{i}" for i in range(1200)])
    assert len(result) == 1200
    # 1200 new keys fit in three 499-operation batches, with no per-document writes.
    assert client.counters["batch_commits"] == 3
    assert client.counters["doc_creates"] == 0


def test_batch_race_resolves_to_the_winner(backend):
    keystore, client = backend
    winner = b"w" * 32

    def interloper():
        client.store("gdpr_officer_keys")["c-x"] = {
            "key_bytes": winner,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    client.before_commit = interloper
    result = keystore.batch_get_or_create(["c-x", "c-y"])
    # The interloper's key survives; c-y still gets one.
    assert result["c-x"].key_bytes == winner
    assert client.store("gdpr_officer_keys")["c-x"]["key_bytes"] == winner
    assert len(result["c-y"].key_bytes) == 32


# ── delete_key, deletion log, filter_forgotten ───────────────────────

def test_delete_key_removes_key_and_logs(backend):
    keystore, client = backend
    keystore.create_key("c-1")
    record = keystore.delete_key("c-1", reason="Art. 17", requested_by="dpo@co.com")
    assert keystore.get_key("c-1") is None
    assert "c-1" not in client.store("gdpr_officer_keys")
    assert [r.customer_id for r in keystore.get_deletion_log()] == ["c-1"]
    assert record.reason == "Art. 17"


def test_delete_missing_key_raises(backend):
    keystore, _ = backend
    with pytest.raises(KeyError):
        keystore.delete_key("ghost", reason="r", requested_by="x")


def test_filter_forgotten_chunks_in_queries(backend):
    keystore, _ = backend
    for cid in ("c-5", "c-40", "c-64"):
        keystore.create_key(cid)
        keystore.delete_key(cid, reason="erasure", requested_by="dpo")
    # 70 ids exceed Firestore's 30-value limit for 'in', so this only works
    # if the query is split into several.
    forgotten = keystore.filter_forgotten([f"c-{i}" for i in range(70)])
    assert forgotten == {"c-5", "c-40", "c-64"}
    assert keystore.filter_forgotten([]) == set()


# ── Engine integration ───────────────────────────────────────────────

def test_erasure_holds_through_the_engine(monkeypatch):
    holder = {}

    def factory(project, database="(default)"):
        holder["client"] = FakeClient(project, database)
        return holder["client"]

    monkeypatch.setattr(firestore_backend.firestore, "Client", factory)
    officer = PiiEncryptor(
        key_backend="gcp_firestore",
        key_backend_config={"project": "test-project"},
    )

    df = pd.DataFrame([
        {"cid": "alice", "email": "alice@example.com"},
        {"cid": "bob", "email": "bob@example.com"},
    ])
    officer.encrypt_df(df, customer_id="cid", pii=["email"])
    officer.forget("bob", reason="Art. 17", requested_by="dpo@co.com")

    returning = pd.DataFrame([{"cid": "bob", "email": "bob@example.com"}])
    with pytest.raises(ForgottenCustomerError):
        officer.encrypt_df(returning, customer_id="cid", pii=["email"])
    assert officer.is_forgotten("bob")
