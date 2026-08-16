"""
Generalisers: generalise a sensitive value to be used for analytics.
A generalised column must also be a pii column.
The generalised value is written to a new target column, next to the encrypted original.

Use them directly:

    officer.encrypt_df(df, customer_id="cid", pii=["email", "birthdate"],
                       generalise={"birthdate": ("age_group", age_group())})

or declare them in a source's generalise section in YAML.

An unmapped or unparseable value never falls back to the raw value:
rules return their configured default, or None.
"""

from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime, timezone
from itertools import pairwise
from typing import Any

Generaliser = Callable[[Any], Any]
GeneraliseSpec = Mapping[str, "Generaliser | tuple[str, Generaliser]"]
"""A generalise argument: column -> callable, or column -> (target column, callable)."""


def _num(value: float) -> str:
    """Format a band edge without a trailing .0 for whole numbers."""
    return str(int(value)) if float(value).is_integer() else str(value)


def _band_labels(edges: Sequence[float], labels: Sequence[str] | None) -> list[str]:
    """Build or validate labels for a set of ascending band edges."""
    starts = list(edges)
    if len(starts) < 2 or starts != sorted(starts) or len(set(starts)) != len(starts):
        raise ValueError("edges must be at least two ascending, distinct numbers")

    expected = len(starts)
    if labels is not None:
        if len(labels) != expected:
            raise ValueError(f"labels must have {expected} entries for {expected - 1} edges")
        return list(labels)

    built = [f"{_num(lo)}-{_num(hi - 1)}" for lo, hi in pairwise(starts)]
    built.append(f"{_num(starts[-1])}+")
    return built


def age_group(
    edges: Sequence[int] = (0, 18, 30, 40, 50, 60, 70),
    as_of: str | date | None = None,
    labels: Sequence[str] | None = None,
) -> Generaliser:
    """
    Map a birthdate to a labelled age group.

    edges are ascending group starts and the last group is open-ended, so the
    default produces 0-17, 18-29, 30-39, 40-49, 50-59, 60-69, 70+. Pass labels
    to name the groups yourself, one per group.

    Accepts a date, a datetime, or an ISO date string. Empty values, values
    that will not parse, and ages below the first edge return None.
    """
    starts = list(edges)
    group_labels = _band_labels(starts, labels)
    fixed_as_of = date.fromisoformat(as_of) if isinstance(as_of, str) else as_of

    def to_group(value: Any) -> str | None:
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            born = value.date()
        elif isinstance(value, date):
            born = value
        elif isinstance(value, str):
            try:
                born = date.fromisoformat(value[:10])
            except ValueError:
                return None
        else:
            raise TypeError(f"age_group expects a date or ISO string, got {type(value).__name__}")

        today = fixed_as_of or datetime.now(timezone.utc).date()
        age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
        if age < starts[0]:
            return None
        for (lo, hi), label in zip(pairwise(starts), group_labels, strict=False):
            if lo <= age < hi:
                return label
        return group_labels[-1]

    return to_group


def mapping(
    values: dict[Any, Any],
    default: Any = None,
) -> Generaliser:
    """
    Replace a value using a lookup table.

    Values not in the table become default, never the original value. Lookup
    falls back to the value's string form, so YAML keys written as strings
    still match numeric data.
    """
    if not values:
        raise ValueError("mapping requires a non-empty values table")
    as_text = {str(k): v for k, v in values.items()}

    def to_mapped(value: Any) -> Any:
        if value is None or value == "":
            return default
        if value in values:
            return values[value]
        return as_text.get(str(value), default)

    return to_mapped


def numeric_range(
    edges: Sequence[float],
    labels: Sequence[str] | None = None,
    default: Any = None,
) -> Generaliser:
    """
    Map a number to a labelled range.

    edges are ascending range starts and the last range is open-ended, so
    [0, 1000, 5000] produces 0-999, 1000-4999, 5000+. Values below the first
    edge, and values that are not numbers, become default.
    """
    starts = list(edges)
    range_labels = _band_labels(starts, labels)

    def to_range(value: Any) -> Any:
        if value is None or value == "":
            return default
        try:
            number = float(value)
        except (TypeError, ValueError):
            return default
        if number < starts[0]:
            return default
        for (lo, hi), label in zip(pairwise(starts), range_labels, strict=False):
            if lo <= number < hi:
                return label
        return range_labels[-1]

    return to_range


def truncate(length: int, default: Any = None) -> Generaliser:
    """
    Keep the first length characters of a value, e.g. a postcode to its area.

    Empty values become default. Values shorter than length are returned as
    they are.
    """
    if length < 1:
        raise ValueError("truncate length must be at least 1")

    def to_prefix(value: Any) -> Any:
        if value is None or value == "":
            return default
        return str(value)[:length]

    return to_prefix


# Rules available in YAML, mapped to the factory that builds them.
RULES: dict[str, Callable[..., Generaliser]] = {
    "age_group": age_group,
    "mapping": mapping,
    "numeric_range": numeric_range,
    "truncate": truncate,
}


def build_rule(column: str, spec: dict[str, Any]) -> tuple[str, Generaliser]:
    """
    Build one (target_column, generaliser) pair from a YAML generalise entry.

    The entry names a rule and its settings, and sets 'to' to the column the
    coarse value is written to. An entry without 'to' is rejected later, when
    the spec is checked against the source's columns.
    """
    if not isinstance(spec, dict):
        raise TypeError(f"generalise['{column}'] must be a mapping of settings")

    settings = dict(spec)
    rule_name = settings.pop("rule", None)
    target = settings.pop("to", column)

    if rule_name is None:
        raise ValueError(f"generalise['{column}'] is missing 'rule'")
    if rule_name not in RULES:
        available = ", ".join(sorted(RULES))
        raise ValueError(f"generalise['{column}']: unknown rule '{rule_name}'. Available: {available}")
    if not isinstance(target, str) or not target:
        raise ValueError(f"generalise['{column}']: 'to' must be a column name")

    try:
        generaliser = RULES[rule_name](**settings)
    except TypeError as e:
        raise ValueError(f"generalise['{column}'] ({rule_name}): {e}") from e

    return target, generaliser


def build_spec(raw: dict[str, dict[str, Any]]) -> dict[str, tuple[str, Generaliser]]:
    """Build the generalise spec for a source from its YAML generalise section."""
    return {column: build_rule(column, spec) for column, spec in raw.items()}


def normalise_generalise(
    generalise: GeneraliseSpec, customer_id_column: str, pii_columns: list[str]
) -> dict[str, tuple[str, Generaliser]]:
    """
    Normalise generalise entries to source -> (target, callable) and validate
    the spec. Raises ValueError for an entry that touches the customer id
    column, names a source that is not a pii column, has no target column, or
    writes to a pii column or to a target another entry already writes to.
    """
    spec: dict[str, tuple[str, Generaliser]] = {}
    for src, value in generalise.items():
        if isinstance(value, tuple):
            target, fn = value
        else:
            target, fn = src, value
        if not callable(fn):
            raise TypeError(f"generalise['{src}'] is not callable")
        if src == customer_id_column or target == customer_id_column:
            raise ValueError(f"cannot generalise the customer_id_column '{customer_id_column}'")
        if src not in pii_columns:
            raise ValueError(f"generalise source '{src}' must also be listed in pii_columns")
        if target == src:
            raise ValueError(f"generalise entry '{src}' needs a target column ('to')")
        if target in pii_columns:
            raise ValueError(
                f"generalise target '{target}' is also a pii_column; pick a new column name"
            )
        spec[src] = (target, fn)

    targets = [target for target, _ in spec.values()]
    if len(targets) != len(set(targets)):
        raise ValueError("two generalise entries write to the same column")
    for target in targets:
        if target in spec and spec[target][0] != target:
            raise ValueError(f"generalise target '{target}' is also a source column")
    return spec
