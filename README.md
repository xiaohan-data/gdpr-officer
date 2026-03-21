# gdpr-officer

gdpr-officer solves GDPR-compliant data erasure with a single operation, making PII permanently unreadable across all tables when the "right to be forgotten" is invoked — without modifying or deleting any data, preserving analytics integrity. It also protects sensitive data during breaches and leaks.

Erasing a customer's PII from a data lake/house across multiple tables is difficult. Finding and deleting every copy is cumbersome, error-prone, and breaks referential integrity.

gdpr-officer uses the [crypto-shredding](https://en.wikipedia.org/wiki/Crypto-shredding) pattern. Delete a key, forget a customer. It:

- encrypts PII with a unique encryption key per customer before data is loaded into the platform, restricting access and protecting it during leaks;
- stores encryption keys in a separate key store outside the data platform, ensuring PII stays unreadable even when the lake/house is breached;
- when GDPR erasure is requested, forgets the customer by deleting their encryption key, rendering their PII permanently undecryptable across every table, while non-PII columns remain intact for analytics;
- enables authorised decryption for any customer whose key is maintained.

## Install

```bash
pip install gdpr-officer              # Core library with local DuckDB backend
pip install gdpr-officer[gcp]         # Adds Google Cloud Firestore backend
```

## How it works

```
Source → Extract → gdpr-officer → Load (PII encrypted) → Data Platform → dbt
                       ↕
               Separate Key Store
          (outside the data platform)
```

gdpr-officer sits between your extract and load steps. It encrypts PII columns using AES-256-GCM with a unique 32-byte key per customer. Each value gets its own random nonce, so identical plaintext produces a different ciphertext each time, to avoid pattern detection. The encrypted output is a base64 string containing the nonce and ciphertext.

The encryption key is stored separately outside the data platform. Even with full access to the data lake/house, PII cannot be decrypted without the key store.

## Usage

### Encrypt

Add between your extract and load steps. `customer_id` takes the identifier column. `pii` takes a list of columns to encrypt. Everything else passes through unchanged.
For repeated use across multiple sources, these can be defined in a YAML configuration file.

```python
from gdpr_officer import PiiEncryptor

officer = PiiEncryptor(
    key_backend="gcp_firestore",
    key_backend_config={"project": "my-gcp-project"},
)

df = extract_from_source()
df = officer.encrypt_df(
    df,
    customer_id="<your_customer_id_column>",
    pii=["<pii_column_1>", "<pii_column_2>", ...],
)
load_to_warehouse(df)
```

Lists of dicts and single rows are also supported:

```python
rows = officer.encrypt_rows(rows, customer_id="...", pii=[...])
row = officer.encrypt_row(row, customer_id="...", pii=[...])
```

### Forget

When a GDPR erasure request arrives, call `forget()` with the customer's identifier. This deletes their encryption key from the key store and writes an audit record. After deletion, every encrypted PII value for that customer across every table in the data lake/house is permanently undecryptable. Non-PII columns remain intact.

```python
officer.forget("<customer_id>", reason="GDPR Article 17 request", requested_by="dpo@company.com")
```

Or via the CLI:

```bash
gdpr-officer forget <customer_id> --reason "GDPR Article 17 request" --by "dpo@company.com"
```

### Decrypt

Decrypt PII columns when needed. Pass the same `customer_id` and `pii` parameters used during encryption.

```python
decrypted_df = officer.decrypt_df(df, customer_id="...", pii=[...])
```

If a customer has been forgotten, `decrypt_df` leaves their PII columns as the encrypted base64 strings — the rest of the DataFrame comes back normally. `decrypt_row` raises a `KeyError` instead, so you can decide how to handle a missing key in your code.

## Key store backends

| Backend | Install | Storage | Use for |
|---------|---------|---------|---------|
| `local` | Included | DuckDB file | Development and testing |
| `gcp_firestore` | `pip install gdpr-officer[gcp]` | Google Cloud Firestore | Production on GCP |

### Local (development)

The default backend stores keys in a local DuckDB file. No cloud setup needed. A warning is logged when this backend is active.

```python
officer = PiiEncryptor()  # Defaults to local backend
```

You can inspect the key store with DuckDB:

```python
import duckdb
conn = duckdb.connect("gdpr_officer_keys.duckdb")
print(conn.execute("SELECT * FROM customer_keys").fetchdf())
print(conn.execute("SELECT * FROM deletion_log").fetchdf())
```

### GCP Firestore (production)

Create a Firestore database and configure IAM:

```bash
gcloud firestore databases create --location=<region>

# Pipeline service account — reads and writes keys during encryption
gcloud projects add-iam-policy-binding <project> \
    --member="serviceAccount:<pipeline-sa>@<project>.iam.gserviceaccount.com" \
    --role="roles/datastore.user"

# DPO / compliance — deletes keys for GDPR erasure
gcloud projects add-iam-policy-binding <project> \
    --member="user:<dpo-email>" \
    --role="roles/datastore.user"
```

```python
officer = PiiEncryptor(
    key_backend="gcp_firestore",
    key_backend_config={"project": "<project>", "database": "(default)"},
)
```

## Key migration

Copy keys from one backend to another. The exact key bytes are preserved, so data encrypted through the source backend can be decrypted through the target.

```python
from gdpr_officer import PiiEncryptor, migrate_keys

source = PiiEncryptor(key_backend="local", key_backend_config={"db_path": "keys.duckdb"})
target = PiiEncryptor(key_backend="gcp_firestore", key_backend_config={"project": "<project>"})

result = migrate_keys(source=source, target=target)
```

## Audit trail

Every `forget()` call writes an audit record to the key store.

```python
officer.get_deletion_log()           # All erasure records
officer.is_forgotten("<customer_id>") # Whether a customer's key has been deleted
officer.list_active_customers()      # All customers with active keys
```

```bash
gdpr-officer audit-log
gdpr-officer audit-log --format json
gdpr-officer check <customer_id>
gdpr-officer list-customers
```

## Development

```bash
git clone https://github.com/xiaohan-data/gdpr-officer
cd gdpr-officer
pip install -e ".[dev]"
pytest
```

The example scripts show the full encrypt → forget → decrypt lifecycle with sample data:

```bash
python examples/demo.py          # Minimal pipeline example
python examples/local_test.py    # Detailed inspection of encrypted output and key store
```

## API reference

| Method | Description |
|--------|-------------|
| `PiiEncryptor(key_backend, key_backend_config)` | Create an encryptor with the specified key store backend |
| `encrypt_df(df, customer_id, pii)` | Encrypt PII columns in a pandas DataFrame |
| `encrypt_rows(rows, customer_id, pii)` | Encrypt PII columns in a list of dicts |
| `encrypt_row(row, customer_id, pii)` | Encrypt PII columns in a single dict |
| `decrypt_df(df, customer_id, pii)` | Decrypt PII columns; forgotten customers' values stay encrypted |
| `decrypt_row(row, customer_id, pii)` | Decrypt PII columns; raises `KeyError` if customer was forgotten |
| `forget(customer_id, reason, requested_by)` | Delete a customer's encryption key and log the erasure |
| `is_forgotten(customer_id)` | Check whether a customer's key has been deleted |
| `list_active_customers()` | List all customer IDs with active keys |
| `get_deletion_log()` | Return all erasure audit records |
| `migrate_keys(source, target)` | Copy keys between backends preserving exact key bytes |

## CLI reference

```bash
gdpr-officer forget <customer_id> --reason "..." --by "..."    # Delete a customer's key
gdpr-officer check <customer_id>                                # Check if a customer was forgotten
gdpr-officer list-customers                                     # List active customer keys
gdpr-officer audit-log [--format json]                          # Show erasure audit log
```

## Roadmap

- [ ] AWS DynamoDB backend
- [ ] Azure Table Storage backend
- [ ] Key rotation with batch re-encryption
- [ ] Decryption utilities for controlled PII access workflows

## License

Apache 2.0