"""
Example: How gdpr-officer fits into a data pipeline.

Simulates extract → encrypt → load, then GDPR erasure.
"""

import pandas as pd

from gdpr_officer import PiiEncryptor

# ── Setup ────────────────────────────────────────────────────────────

officer = PiiEncryptor(
    key_backend="local",
    key_backend_config={"db_path": ":memory:"},
)

# ── Extract (your existing code, unchanged) ──────────────────────────

raw = pd.DataFrame([
    {"patient_number": "pa-001", "ssn": "110478-2356", "address": "Andevej 1",   "diagnosis": "MS",  "billing_amount": 10},
    {"patient_number": "pa-002", "ssn": "230896-1145", "address": "Lysvej 56",   "diagnosis": "CFR", "billing_amount": 145},
    {"patient_number": "pa-003", "ssn": "020756-7748", "address": "Givevej 17",  "diagnosis": "PIR", "billing_amount": 453678},
])

print("=== Raw data ===")
print(raw.to_string(index=False))

# ── Encrypt (one line added) ─────────────────────────────────────────

encrypted = officer.encrypt_df(raw, customer_id="patient_number", pii=["ssn", "address", "diagnosis"])

print("\n=== Encrypted (what lands in warehouse) ===")
display = encrypted.copy()
for col in ["ssn", "address", "diagnosis"]:
    display[col] = display[col].str[:20] + "..."
print(display.to_string(index=False))

# ── Load (your existing code, unchanged) ─────────────────────────────
# load_to_bigquery(encrypted, "raw.customers")

# ── GDPR erasure ─────────────────────────────────────────────────────

print("\n=== Forgetting patient pa-003 ===")
officer.forget("pa-003", reason="GDPR Article 17", requested_by="dpo@company.dk")

# ── Decrypt ──────────────────────────────────────────────────────────

print("\n=== Decryption ===")
decrypted = officer.decrypt_df(encrypted, customer_id="patient_number", pii=["ssn", "address", "diagnosis"])

for _, row in decrypted.iterrows():
    cid = row["patient_number"]
    if officer.is_forgotten(cid):
        print(f"  {cid}: [FORGOTTEN] billing_amount={row['billing_amount']}")
    else:
        print(f"  {cid}: ssn={row['ssn']}, address={row['address']}, billing_amount={row['billing_amount']}")

# ── Audit log ────────────────────────────────────────────────────────

print("\n=== Audit log ===")
for r in officer.get_deletion_log():
    print(f"  [{r.deleted_at.isoformat()}] {r.customer_id} — {r.reason}")
