"""
Tests for the generalisation rules and for applying them through the API.
"""

from datetime import date, datetime, timezone

import pandas as pd
import pytest

from gdpr_officer import PiiEncryptor, age_group, mapping, numeric_range, truncate


@pytest.fixture
def officer():
    return PiiEncryptor(key_backend="local", key_backend_config={"db_path": ":memory:"})


GROUP = age_group(as_of="2026-07-01")

ROWS = [
    {"cid": "c-1", "email": "a@example.com", "birthdate": "1982-01-15", "revenue": 3200},
    {"cid": "c-2", "email": "b@example.com", "birthdate": "2003-01-25", "revenue": 300},
]


# ---------------------------------------------------------------------------
# age_group
# ---------------------------------------------------------------------------

def test_age_group_default_edges():
    band = age_group(as_of="2026-07-01")
    assert band("1982-01-15") == "40-49"
    assert band("2003-01-25") == "18-29"
    assert band("2015-06-30") == "0-17"
    assert band("1950-01-01") == "70+"


def test_age_group_accepts_dates_and_datetimes():
    band = age_group(as_of=date(2026, 7, 1))
    assert band(date(1982, 1, 15)) == "40-49"
    assert band(datetime(1982, 1, 15, 8, 30, tzinfo=timezone.utc)) == "40-49"


def test_age_group_none_empty_and_future():
    band = age_group(as_of="2026-07-01")
    assert band(None) is None
    assert band("") is None
    # A future birthdate has no meaningful age.
    assert band("2030-01-01") is None


def test_age_group_custom_edges_and_bad_input():
    band = age_group(edges=(18, 65), as_of="2026-07-01")
    assert band("1990-01-01") == "18-64"
    assert band("1950-01-01") == "65+"
    with pytest.raises(TypeError):
        band(12345)
    with pytest.raises(ValueError):
        age_group(edges=(30,))
    with pytest.raises(ValueError):
        age_group(edges=(30, 20))


# ---------------------------------------------------------------------------
# mapping
# ---------------------------------------------------------------------------

def test_mapping_unmapped_never_leaks_original():
    to_region = mapping({"EMEA": ["NL", "DE"], "APAC": ["AU"]}, default="Other")
    assert to_region("NL") == "EMEA"
    assert to_region("AU") == "APAC"
    # An unlisted value must not fall through as the original value.
    assert to_region("US") == "Other"
    assert to_region(None) == "Other"


def test_mapping_string_form_matches_numeric_data():
    to_band = mapping({"low": [1, 2], "high": [3]})
    assert to_band("2") == "low"
    assert to_band(3) == "high"


def test_mapping_requires_a_group():
    with pytest.raises(ValueError, match="at least one non-empty group"):
        mapping({})
    with pytest.raises(ValueError, match="at least one non-empty group"):
        mapping({"EMEA": []})


def test_mapping_rejects_value_in_two_groups():
    with pytest.raises(ValueError, match="is in both"):
        mapping({"EMEA": ["NL"], "APAC": ["NL"]})


def test_mapping_rejects_string_members():
    with pytest.raises(TypeError, match="list of values"):
        mapping({"EMEA": "NL"})


# ---------------------------------------------------------------------------
# numeric_range
# ---------------------------------------------------------------------------

def test_numeric_range_labels_and_defaults():
    to_range = numeric_range([0, 50000, 100000, 200000])
    assert to_range(0) == "0-49999"
    assert to_range(75000) == "50000-99999"
    assert to_range(250000) == "200000+"
    assert to_range("75000") == "50000-99999"
    assert to_range(-5) is None
    assert to_range("not a number") is None


def test_numeric_range_custom_labels():
    to_range = numeric_range([0, 100, 1000], labels=["small", "medium", "large"])
    assert to_range(50) == "small"
    assert to_range(5000) == "large"
    with pytest.raises(ValueError, match="labels must have"):
        numeric_range([0, 100, 1000], labels=["only", "two"])


# ---------------------------------------------------------------------------
# truncate
# ---------------------------------------------------------------------------

def test_truncate():
    to_area = truncate(2)
    assert to_area("2000") == "20"
    assert to_area(None) is None
    assert to_area("1") == "1"
    with pytest.raises(ValueError, match="at least 1"):
        truncate(0)


# ---------------------------------------------------------------------------
# Applying generalisation through the API
# ---------------------------------------------------------------------------

def test_generalising_adds_a_column_and_keeps_the_encrypted_original(officer):
    out = officer.encrypt_rows(
        ROWS, customer_id="cid", pii=["email", "birthdate"],
        generalise={"birthdate": ("age_group", GROUP)},
    )
    row = out[0]
    assert row["age_group"] == "40-49"
    # The exact birthdate is still there, as ciphertext.
    assert row["birthdate"].startswith("Z2Rwci1vZmZpY2Vy")
    # The new column sits next to the column it came from.
    assert list(row) == ["cid", "email", "birthdate", "age_group", "revenue"]
    decrypted = officer.decrypt_row(row, customer_id="cid", pii=["email", "birthdate"])
    assert decrypted["birthdate"] == "1982-01-15"
    assert decrypted["age_group"] == "40-49"


def test_generaliser_receives_plaintext_not_ciphertext(officer):
    # postcode is both encrypted and generalised. If encryption ran first, the
    # mapping would see ciphertext, match nothing, and collapse to the default.
    out = officer.encrypt_rows(
        [{"cid": "c-1", "postcode": "2000"}],
        customer_id="cid", pii=["postcode"],
        generalise={"postcode": ("state", mapping({"NSW": ["2000"]}, default="Other"))},
    )
    row = out[0]
    assert row["state"] == "NSW"
    assert row["postcode"].startswith("Z2Rwci1vZmZpY2Vy")
    assert officer.decrypt_row(row, customer_id="cid", pii=["postcode"])["postcode"] == "2000"


def test_df_columns_and_analytics(officer):
    df = pd.DataFrame(ROWS)
    enc = officer.encrypt_df(
        df, customer_id="cid", pii=["email", "birthdate"],
        generalise={"birthdate": ("age_group", GROUP)},
    )
    assert list(enc.columns) == ["cid", "email", "birthdate", "age_group", "revenue"]
    by_group = enc.groupby("age_group")["revenue"].sum()
    assert by_group["40-49"] == 3200
    assert by_group["18-29"] == 300


def test_encrypt_row_single_path(officer):
    row = officer.encrypt_row(
        dict(ROWS[0]), customer_id="cid", pii=["email", "birthdate"],
        generalise={"birthdate": ("age_group", GROUP)},
    )
    assert row["age_group"] == "40-49"
    assert row["birthdate"].startswith("Z2Rwci1vZmZpY2Vy")


# ---------------------------------------------------------------------------
# Validation and error handling
# ---------------------------------------------------------------------------

def test_source_must_also_be_encrypted(officer):
    # Forgetting to encrypt the source would silently drop the original.
    with pytest.raises(ValueError, match="must also be listed in pii_columns"):
        officer.encrypt_rows(
            ROWS, customer_id="cid", pii=["email"],
            generalise={"birthdate": ("age_group", GROUP)},
        )


def test_target_column_is_required(officer):
    # Without 'to' the coarse value would overwrite the value being encrypted.
    with pytest.raises(ValueError, match="needs a target column"):
        officer.encrypt_rows(
            ROWS, customer_id="cid", pii=["email", "birthdate"],
            generalise={"birthdate": GROUP},
        )


def test_generalise_validation_errors(officer):
    with pytest.raises(ValueError, match="cannot generalise the customer_id_column"):
        officer.encrypt_rows(
            ROWS, customer_id="cid", pii=["email"], generalise={"cid": GROUP},
        )
    with pytest.raises(TypeError, match="not callable"):
        officer.encrypt_rows(
            ROWS, customer_id="cid", pii=["email", "birthdate"],
            generalise={"birthdate": "oops"},
        )
    with pytest.raises(ValueError, match="same column"):
        officer.encrypt_rows(
            ROWS, customer_id="cid", pii=["email", "birthdate"],
            generalise={"birthdate": ("x", GROUP), "email": ("x", GROUP)},
        )


def test_target_colliding_with_a_pii_column_rejected(officer):
    with pytest.raises(ValueError, match="pick a new column name"):
        officer.encrypt_rows(
            ROWS, customer_id="cid", pii=["email", "birthdate"],
            generalise={"birthdate": ("email", truncate(4))},
        )


def test_row_level_errors_surface(officer):
    # Missing source column and an existing target column are row errors.
    with pytest.raises(RuntimeError, match="not in row"):
        officer.encrypt_rows(
            [{"cid": "c-9", "email": "x@example.com"}],
            customer_id="cid", pii=["email", "birthdate"],
            generalise={"birthdate": ("age_group", GROUP)},
        )
    with pytest.raises(RuntimeError, match="already exists"):
        officer.encrypt_rows(
            [{"cid": "c-9", "email": "x@example.com", "birthdate": "1990-01-01", "age_group": "?"}],
            customer_id="cid", pii=["email", "birthdate"],
            generalise={"birthdate": ("age_group", GROUP)},
        )


def test_generalise_with_skip_mode(tmp_path):
    db_path = str(tmp_path / "keys.duckdb")
    officer = PiiEncryptor(key_backend="local", key_backend_config={"db_path": db_path})
    officer.encrypt_rows(ROWS, customer_id="cid", pii=["email"])
    officer.forget("c-1", reason="erasure", requested_by="privacy@co.com.au")

    skipping = PiiEncryptor(
        key_backend="local",
        key_backend_config={"db_path": db_path},
        on_forgotten="skip",
    )
    out = skipping.encrypt_rows(
        ROWS, customer_id="cid", pii=["email", "birthdate"],
        generalise={"birthdate": ("age_group", GROUP)},
    )
    assert len(out) == 1
    assert out[0]["cid"] == "c-2"
    assert out[0]["age_group"] == "18-29"
