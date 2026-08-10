"""
Tests for the CLI encrypt command's row-error reporting.
"""

import json

import pytest
from click.testing import CliRunner

from gdpr_officer.cli import main

CONFIG = (
    "customer_identifier: cid\n"
    "key_backend: local\n"
    "key_backend_config:\n"
    "  db_path: keys.duckdb\n"
    "sources:\n"
    "  - name: customers\n"
    "    customer_id_column: cid\n"
    "    pii_columns: [email]\n"
)


@pytest.fixture
def runner():
    r = CliRunner()
    with r.isolated_filesystem():
        with open("gdpr_officer.yaml", "w") as f:
            f.write(CONFIG)
        yield r


def test_encrypt_success_exits_zero(runner):
    with open("in.json", "w") as f:
        json.dump([{"cid": "c-1", "email": "a@example.com"}], f)
    result = runner.invoke(main, ["encrypt", "-s", "customers", "-i", "in.json", "-o", "out.json"])
    assert result.exit_code == 0
    assert "Encrypted 1/1 rows." in result.output
    assert "failed" not in result.output


def test_encrypt_reports_row_errors_and_fails(runner):
    # A ragged export: the second row has no customer id.
    with open("in.json", "w") as f:
        json.dump([{"cid": "c-1", "email": "ok@example.com"}, {"email": "orphan@example.com"}], f)
    result = runner.invoke(main, ["encrypt", "-s", "customers", "-i", "in.json", "-o", "out.json"])
    assert result.exit_code == 1
    assert "1 row(s) failed" in result.output
    assert "row 1" in result.output
    # Successful rows are still written before the failure is reported.
    with open("out.json") as f:
        assert [r["cid"] for r in json.load(f)] == ["c-1"]
