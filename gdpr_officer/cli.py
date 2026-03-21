"""
CLI for gdpr-officer.

Usage:
    gdpr-officer forget <customer_id> --reason "GDPR Art.17" --by "dpo@co.com"
    gdpr-officer check <customer_id>
    gdpr-officer list-customers
    gdpr-officer audit-log
    gdpr-officer encrypt --source customers --input data.json --output encrypted.json
"""

from __future__ import annotations

import json
import sys

import click

from gdpr_officer.api import PiiEncryptor


def _load(config: str) -> PiiEncryptor:
    try:
        return PiiEncryptor.from_config(config)
    except FileNotFoundError:
        click.echo(f"Error: Config file not found: {config}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)


@click.group()
@click.option(
    "--config", "-c",
    default="gdpr_officer.yaml",
    help="Path to config file.",
    envvar="GDPR_OFFICER_CONFIG",
)
@click.pass_context
def main(ctx, config):
    """gdpr-officer: Per-customer PII encryption for data warehouses."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config


@main.command()
@click.argument("customer_id")
@click.option("--reason", "-r", required=True, help="Reason for erasure.")
@click.option("--by", "-b", "requested_by", required=True, help="Who requested erasure.")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt.")
@click.pass_context
def forget(ctx, customer_id, reason, requested_by, confirm):
    """Cryptographically erase a customer by deleting their encryption key."""
    enc = _load(ctx.obj["config_path"])

    if enc.is_forgotten(customer_id):
        click.echo(f"Customer '{customer_id}' has already been forgotten.")
        return

    if not confirm:
        click.echo(f"This will permanently delete the encryption key for '{customer_id}'.")
        click.echo("All PII encrypted with this key becomes PERMANENTLY UNRECOVERABLE.")
        if not click.confirm("Proceed?"):
            click.echo("Aborted.")
            return

    record = enc.forget(customer_id, reason, requested_by)
    click.echo(f"Customer '{customer_id}' has been cryptographically erased.")
    click.echo(f"  Deleted at: {record.deleted_at.isoformat()}")


@main.command("list-customers")
@click.pass_context
def list_customers(ctx):
    """List all customers with active encryption keys."""
    enc = _load(ctx.obj["config_path"])
    customers = enc.list_active_customers()

    if not customers:
        click.echo("No active customer keys.")
        return

    click.echo(f"Active keys ({len(customers)}):")
    for cid in customers:
        click.echo(f"  {cid}")


@main.command("audit-log")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.pass_context
def audit_log(ctx, fmt):
    """Show the GDPR erasure audit log."""
    enc = _load(ctx.obj["config_path"])
    log = enc.get_deletion_log()

    if not log:
        click.echo("No deletions recorded.")
        return

    if fmt == "json":
        records = [
            {
                "customer_id": r.customer_id,
                "deleted_at": r.deleted_at.isoformat(),
                "reason": r.reason,
                "requested_by": r.requested_by,
            }
            for r in log
        ]
        click.echo(json.dumps(records, indent=2))
    else:
        click.echo(f"Deletion log ({len(log)} records):")
        for r in log:
            click.echo(
                f"  [{r.deleted_at.isoformat()}] {r.customer_id} "
                f"— {r.reason} (by {r.requested_by})"
            )


@main.command()
@click.argument("customer_id")
@click.pass_context
def check(ctx, customer_id):
    """Check whether a customer has been forgotten."""
    enc = _load(ctx.obj["config_path"])

    if enc.is_forgotten(customer_id):
        click.echo(f"FORGOTTEN: '{customer_id}' — PII permanently unrecoverable.")
    else:
        click.echo(f"ACTIVE: '{customer_id}' has an encryption key.")


@main.command()
@click.option("--source", "-s", required=True)
@click.option("--input", "-i", "input_file", required=True)
@click.option("--output", "-o", "output_file", required=True)
@click.pass_context
def encrypt(ctx, source, input_file, output_file):
    """Encrypt PII columns in a JSON data file."""
    enc = _load(ctx.obj["config_path"])

    with open(input_file) as f:
        rows = json.load(f)

    result = enc.encrypt_batch(rows, source)

    with open(output_file, "w") as f:
        json.dump(result.rows, f, indent=2)

    click.echo(f"Encrypted {result.encrypted_rows}/{result.total_rows} rows.")
    if result.new_keys_created:
        click.echo(f"New keys created: {result.new_keys_created}")


if __name__ == "__main__":
    main()
