"""
Local test: see exactly what the encryption produces and what's in the key store.

Run from the gdpr-officer directory:
    python examples/local_test.py

After running, inspect the DuckDB file yourself:
    pip install duckdb-cli   (or use Python)
    python -c "import duckdb; print(duckdb.connect('test_keys.duckdb').execute('SELECT * FROM customer_keys').fetchdf())"
"""

import os
import pandas as pd

from gdpr_officer import PiiEncryptor

# Clean up from previous runs
for f in ["test_keys.duckdb", "test_keys.duckdb.wal"]:
    if os.path.exists(f):
        os.remove(f)

# ── Setup with a real DuckDB file (not :memory:) ────────────────────

officer = PiiEncryptor(
    key_backend="local",
    key_backend_config={"db_path": "test_keys.duckdb"},
)

# Access the DuckDB connection through the backend for inspection
db = officer.backend._conn

# ── Sample data ──────────────────────────────────────────────────────

raw = pd.DataFrame([
    {"customer_id": "CUST-001", "email": "alice@example.com",   "phone": "+31612345678", "city": "Amsterdam",  "revenue": 1500},
    {"customer_id": "CUST-002", "email": "bob@company.nl",      "phone": "+31687654321", "city": "Rotterdam",  "revenue": 3200},
    {"customer_id": "CUST-003", "email": "carol@startup.io",    "phone": "+31698765432", "city": "Utrecht",    "revenue": 750},
    {"customer_id": "CUST-001", "email": "alice@example.com",   "phone": "+31612345678", "city": "Amsterdam",  "revenue": 2100},
])

print("=" * 80)
print("RAW DATA (what comes from your source system)")
print("=" * 80)
print(raw.to_string(index=False))

# ── Encrypt ──────────────────────────────────────────────────────────

encrypted = officer.encrypt_df(
    raw,
    customer_id="customer_id",
    pii=["email", "phone"],
)

print("\n" + "=" * 80)
print("ENCRYPTED DATA (what would land in your warehouse)")
print("=" * 80)

# Show truncated for readability
display = encrypted.copy()
display["email"] = display["email"].str[:40] + "..."
display["phone"] = display["phone"].str[:40] + "..."
print(display.to_string(index=False))

print("\nKey observations:")
print("  - email and phone are encrypted, different ciphertext each row")
print("  - customer_id, city, revenue pass through unchanged")
print("  - CUST-001 rows have DIFFERENT ciphertext (random nonce per value)")

# ── Inspect the DuckDB key store ─────────────────────────────────────

print("\n" + "=" * 80)
print("DUCKDB KEY STORE — customer_keys table")
print("=" * 80)

keys_df = db.execute(
    "SELECT customer_id, octet_length(key_bytes) as key_size_bytes, created_at "
    "FROM customer_keys ORDER BY customer_id"
).fetchdf()
print(keys_df.to_string(index=False))

print("\n-- Key bytes as hex (the actual AES-256 keys) --")
hex_df = db.execute(
    "SELECT customer_id, hex(key_bytes) as key_hex "
    "FROM customer_keys ORDER BY customer_id"
).fetchdf()
for _, row in hex_df.iterrows():
    print(f"  {row['customer_id']}: {row['key_hex']}")

print(f"\n3 customers = 3 unique keys, each 32 bytes (256 bits)")

print("\n" + "=" * 80)
print("DUCKDB KEY STORE — deletion_log table")
print("=" * 80)

del_df = db.execute("SELECT * FROM deletion_log").fetchdf()
if len(del_df) == 0:
    print("(empty — no customers forgotten yet)")
else:
    print(del_df.to_string(index=False))

# ── Decrypt roundtrip ────────────────────────────────────────────────

print("\n" + "=" * 80)
print("DECRYPTED DATA (roundtrip proof — original values recovered)")
print("=" * 80)

decrypted = officer.decrypt_df(encrypted, customer_id="customer_id", pii=["email", "phone"])
print(decrypted.to_string(index=False))

match = (decrypted["email"] == raw["email"]).all() and (decrypted["phone"] == raw["phone"]).all()
print(f"\nRoundtrip match: {match}")

# ── Forget CUST-002 ─────────────────────────────────────────────────

print("\n" + "=" * 80)
print("FORGETTING CUST-002 (GDPR erasure)")
print("=" * 80)

officer.forget("CUST-002", reason="GDPR Article 17 request", requested_by="dpo@company.nl")

print("\n-- customer_keys after deletion --")
keys_after = db.execute(
    "SELECT customer_id, created_at FROM customer_keys ORDER BY customer_id"
).fetchdf()
print(keys_after.to_string(index=False))
print("\nCUST-002 is gone from the key table.")

print("\n-- deletion_log now has a record --")
del_after = db.execute("SELECT * FROM deletion_log").fetchdf()
print(del_after.to_string(index=False))

# ── Decrypt after forgetting ─────────────────────────────────────────

print("\n" + "=" * 80)
print("DECRYPT AFTER FORGETTING CUST-002")
print("=" * 80)

decrypted_after = officer.decrypt_df(
    encrypted, customer_id="customer_id", pii=["email", "phone"]
)

for _, row in decrypted_after.iterrows():
    cid = row["customer_id"]
    if officer.is_forgotten(cid):
        print(f"  {cid}: email=<PERMANENTLY UNRECOVERABLE>  phone=<PERMANENTLY UNRECOVERABLE>  revenue={row['revenue']}")
    else:
        print(f"  {cid}: email={row['email']}  phone={row['phone']}  revenue={row['revenue']}")

# ── Close and show file ──────────────────────────────────────────────

print("\n" + "=" * 80)
print("DONE")
print("=" * 80)
print(f"\nDuckDB file saved at: {os.path.abspath('test_keys.duckdb')}")
print(f"File size: {os.path.getsize('test_keys.duckdb')} bytes")
print("\nYou can inspect it later with:")
print('  python -c "import duckdb; c=duckdb.connect(\'test_keys.duckdb\'); print(c.execute(\'SELECT * FROM customer_keys\').fetchdf())"')
print('  python -c "import duckdb; c=duckdb.connect(\'test_keys.duckdb\'); print(c.execute(\'SELECT * FROM deletion_log\').fetchdf())"')
