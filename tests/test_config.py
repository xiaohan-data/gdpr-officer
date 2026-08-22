"""
Tests for configuration: source validation, building generalise rules from YAML, and end-to-end use of a config file.
"""

import pandas as pd
import pytest
import yaml

from gdpr_officer import PiiEncryptor
from gdpr_officer.config import GdprOfficerConfig
from gdpr_officer.generalise import build_rule

ROWS = [
    {"customer_id": "c-1", "email": "a@example.com", "birthdate": "1982-01-15",
     "postcode": "2000", "revenue": 3200},
    {"customer_id": "c-2", "email": "b@example.com", "birthdate": "2003-01-25",
     "postcode": "9999", "revenue": 300},
]

CONFIG = {
    "customer_identifier": "customer_id",
    "key_backend": "local",
    "key_backend_config": {"db_path": ":memory:"},
    "sources": [
        {
            "name": "customers",
            "customer_id_column": "customer_id",
            "pii_columns": ["email", "birthdate", "postcode"],
            "generalise": {
                "birthdate": {
                    "rule": "age_group",
                    "to": "age_group",
                    "edges": [0, 18, 30, 40, 50, 65],
                    "as_of": "2026-07-01",
                },
                "postcode": {
                    "rule": "mapping",
                    "to": "state",
                    "groups": {"NSW": ["2000"], "VIC": ["3000"]},
                    "default": "Other",
                },
            },
        }
    ],
}


def _config(tmp_path, **overrides):
    """A copy of CONFIG with a real key store, plus any overrides."""
    config = {**CONFIG, "key_backend_config": {"db_path": str(tmp_path / "keys.duckdb")}}
    config.update(overrides)
    return config


# ---------------------------------------------------------------------------
# build_rule: turning a YAML entry into a callable
# ---------------------------------------------------------------------------

def test_build_rule_defaults_to_in_place():
    target, fn = build_rule("postcode", {"rule": "truncate", "length": 2})
    assert target == "postcode"
    assert fn("2000") == "20"


def test_build_rule_honours_to():
    target, fn = build_rule(
        "birthdate", {"rule": "age_group", "to": "age_group", "as_of": "2026-07-01"}
    )
    assert target == "age_group"
    assert fn("1982-01-15") == "40-49"


def test_build_rule_errors_are_specific():
    with pytest.raises(ValueError, match="missing 'rule'"):
        build_rule("postcode", {"to": "state"})
    with pytest.raises(ValueError, match="unknown rule"):
        build_rule("postcode", {"rule": "sorcery"})
    with pytest.raises(TypeError, match="must be a mapping"):
        build_rule("postcode", ["not", "a", "dict"])
    # A setting the rule does not accept is reported against that column.
    with pytest.raises(ValueError, match=r"generalise\['postcode'\] \(truncate\)"):
        build_rule("postcode", {"rule": "truncate", "nonsense": 1})


# ---------------------------------------------------------------------------
# Source validation
# ---------------------------------------------------------------------------

def test_config_builds_generalise_spec():
    config = GdprOfficerConfig.from_dict(CONFIG)
    source = config.get_source("customers")
    assert set(source.generalise) == {"birthdate", "postcode"}
    target, fn = source.generalise["birthdate"]
    assert target == "age_group"
    assert fn("1982-01-15") == "40-49"


def test_config_rejects_generalising_the_customer_id():
    bad = {
        **CONFIG,
        "sources": [{
            "name": "customers",
            "customer_id_column": "customer_id",
            "pii_columns": ["email"],
            "generalise": {"customer_id": {"rule": "truncate", "to": "x", "length": 2}},
        }],
    }
    with pytest.raises(ValueError, match="cannot generalise the customer_id_column"):
        GdprOfficerConfig.from_dict(bad)


def test_config_rejects_duplicate_targets():
    bad = {
        **CONFIG,
        "sources": [{
            "name": "customers",
            "customer_id_column": "customer_id",
            "pii_columns": ["email", "postcode", "suburb"],
            "generalise": {
                "postcode": {"rule": "truncate", "to": "area", "length": 2},
                "suburb": {"rule": "truncate", "to": "area", "length": 3},
            },
        }],
    }
    with pytest.raises(ValueError, match="same column"):
        GdprOfficerConfig.from_dict(bad)


def test_config_rejects_target_colliding_with_pii():
    bad = {
        **CONFIG,
        "sources": [{
            "name": "customers",
            "customer_id_column": "customer_id",
            "pii_columns": ["email", "birthdate"],
            "generalise": {"birthdate": {"rule": "truncate", "to": "email", "length": 4}},
        }],
    }
    with pytest.raises(ValueError, match="pick a new column name"):
        GdprOfficerConfig.from_dict(bad)


def test_config_requires_generalise_source_to_be_encrypted():
    # Without this, forgetting the pii entry would silently drop the original.
    bad = {
        **CONFIG,
        "sources": [{
            "name": "customers",
            "customer_id_column": "customer_id",
            "pii_columns": ["email"],
            "generalise": {"birthdate": {"rule": "age_group", "to": "age_group"}},
        }],
    }
    with pytest.raises(ValueError, match="must also be listed in pii_columns"):
        GdprOfficerConfig.from_dict(bad)


def test_config_requires_a_target_column():
    bad = {
        **CONFIG,
        "sources": [{
            "name": "customers",
            "customer_id_column": "customer_id",
            "pii_columns": ["birthdate"],
            "generalise": {"birthdate": {"rule": "age_group"}},
        }],
    }
    with pytest.raises(ValueError, match="needs a target column"):
        GdprOfficerConfig.from_dict(bad)


# ---------------------------------------------------------------------------
# End to end through a config file
# ---------------------------------------------------------------------------

def test_yaml_config_applies_generalisation(tmp_path):
    path = tmp_path / "gdpr_officer.yaml"
    path.write_text(yaml.safe_dump(_config(tmp_path)))

    officer = PiiEncryptor.from_config(path)
    source = officer.config.get_source("customers")
    out = officer.encrypt_rows(
        ROWS,
        customer_id="customer_id",
        pii=source.pii_columns,
        generalise=source.generalise,
    )

    assert out[0]["age_group"] == "40-49"
    assert out[0]["state"] == "NSW"
    # An unmapped postcode takes the default, not the original value.
    assert out[1]["state"] == "Other"
    # The original values are encrypted.
    assert out[0]["birthdate"].startswith("Z2Rwci1vZmZpY2Vy")
    assert out[0]["postcode"].startswith("Z2Rwci1vZmZpY2Vy")
    assert out[0]["email"].startswith("Z2Rwci1vZmZpY2Vy")
    assert out[0]["revenue"] == 3200


def test_encrypt_batch_uses_source_generalise(tmp_path):
    path = tmp_path / "gdpr_officer.yaml"
    path.write_text(yaml.safe_dump(_config(tmp_path)))

    officer = PiiEncryptor.from_config(path)
    # No generalise argument: the source's configured rules apply.
    result = officer.encrypt_batch(ROWS, "customers")

    assert result.encrypted_rows == 2
    assert result.rows[0]["age_group"] == "40-49"
    assert result.rows[0]["state"] == "NSW"
    assert result.rows[0]["birthdate"].startswith("Z2Rwci1vZmZpY2Vy")


def test_encrypt_and_generalise_same_column(tmp_path):
    config = _config(tmp_path, sources=[{
        "name": "customers",
        "customer_id_column": "customer_id",
        "pii_columns": ["email", "birthdate"],
        "generalise": {
            "birthdate": {"rule": "age_group", "to": "age_group", "as_of": "2026-07-01"}
        },
    }])
    officer = PiiEncryptor.from_dict(config)
    row = officer.encrypt_batch(ROWS[:1], "customers").rows[0]

    assert row["age_group"] == "40-49"
    assert row["birthdate"].startswith("Z2Rwci1vZmZpY2Vy")
    decrypted = officer.decrypt_row(
        row, customer_id="customer_id", pii=["email", "birthdate"]
    )
    assert decrypted["birthdate"] == "1982-01-15"


def test_shipped_template_is_valid():
    from pathlib import Path

    import gdpr_officer

    template = Path(gdpr_officer.__file__).parent / "config_template.yaml"
    config = GdprOfficerConfig.from_dict(yaml.safe_load(template.read_text()))
    # Every table in the template loads, including one with no generalise
    # section and one with a differently named customer column.
    assert [s.name for s in config.sources] == ["customers", "invoices"]
    assert config.get_source("invoices").generalise == {}
    assert config.get_source("invoices").customer_id_column == "account_id"

    customers = config.get_source("customers")
    assert customers.pii_columns == [
        "email", "phone", "full_name", "birthdate", "nationality", "amount", "ip_address",
    ]
    # All four rules appear on the first table.
    assert set(customers.generalise) == {"birthdate", "nationality", "amount", "ip_address"}

    df = pd.DataFrame([{
        "customer_id": "c-1", "email": "a@example.com", "phone": "+61 400 000 000",
        "full_name": "Alice Tan", "birthdate": "1982-01-15", "nationality": "DE",
        "amount": 75000, "ip_address": "203.0.113.42",
    }])
    officer = PiiEncryptor(key_backend="local", key_backend_config={"db_path": ":memory:"})
    out = officer.encrypt_df(
        df, customer_id="customer_id", pii=customers.pii_columns,
        generalise=customers.generalise,
    )
    row = out.iloc[0]
    assert row["region"] == "EMEA"
    assert row["amount_range"] == "50000-99999"
    assert row["ip_prefix"] == "203.0.1"
    assert list(out.columns) == [
        "customer_id", "email", "phone", "full_name",
        "birthdate", "age_group", "nationality", "region",
        "amount", "amount_range", "ip_address", "ip_prefix",
    ]
