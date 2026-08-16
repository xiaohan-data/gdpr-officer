# Changelog

All notable changes to this project are documented here.
This project follows semantic versioning.
 
## [0.3.0] - 2026-08-16
 
### Added
- Column generalisation: a generalised version of a PII column to enable analytical use. Written to a new
  column next to the encrypted original. Pass `generalise=` to `encrypt_df`, `encrypt_rows` and
  `encrypt_row`, or declare it per source in YAML.
- Four generalisation rules: `age_group`, `mapping`, `numeric_range`, `truncate`.
- `config_template.yaml`, shipped with the package, showing config
  sections across multiple tables.
- `generalise` section on a source in the config file. `encrypt_batch(rows,
  source)` applies a source's rules automatically.

## [0.2.2] - 2026-08-10
 
### Added
- PyPI trusted-publishing release workflow

## [0.2.1] - 2026-08-10
 
### Fixed
- CLI `encrypt` now reports failed rows to stderr and exits non-zero.

## [0.2.0] - 2026-06-26

### Added
- `filter_forgotten()` on the key backend interface, to check the deletion log.
- `ForgottenCustomerError`, raised when re-encrypting a customer who was previously forgotten.
- `on_forgotten` option ("error" default, or "skip") on PiiEncryptor.

### Changed
- **Breaking:** re-encrypting a forgotten customer_id no longer creates a new
  key. By default it raises ForgottenCustomerError; pass `on_forgotten="skip"`
  to drop their rows instead.
- **Breaking:** `is_forgotten()` now returns True only when a customer has no
  active key *and* appears in the deletion log (previously: customer
  without a key).

### Fixed
- `batch_get_or_create([])` raised a SQL error on an empty batch.
- `decrypt_value("")` now returns "" instead of raising, matching `encrypt_value`.

## [0.1.0] - 2026-03-21

### Added

- Initial release.
- Per-customer AES-256-GCM column encryption via `PiiEncryptor`.
- Local DuckDB key backend (`key_backend="local"`) for development and testing.
- Google Cloud Firestore key backend (`key_backend="gcp_firestore"`) for production.
- `PiiEncryptor.encrypt_row` / `encrypt_rows` / `encrypt_df` — row, batch, and DataFrame encryption APIs.
- `PiiEncryptor.decrypt_row` / `decrypt_df` — decryption APIs; forgotten customers' PII is left as ciphertext.
- `PiiEncryptor.forget(customer_id, reason, requested_by)` — crypto-shredding via key deletion, with audit log.
- `PiiEncryptor.get_deletion_log()` — full audit trail of erasure events.
- `migrate_keys(source, target)` — key migration between backends.
- YAML/dict config support via `GdprOfficerConfig`.
- Named source API (`encrypt`, `decrypt`, `encrypt_batch`) for Python ingestion pipelines.
