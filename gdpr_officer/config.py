"""
Configuration for gdpr-officer.

Optional YAML configuration for defining multiple data sources and their PII columns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class SourceConfig:
    """Configuration for a single data source's PII columns."""

    name: str
    customer_id_column: str
    pii_columns: list[str]
    passthrough_columns: Optional[list[str]] = None

    def validate(self):
        if not self.customer_id_column:
            raise ValueError(f"Source '{self.name}': customer_id_column is required")
        if not self.pii_columns:
            raise ValueError(f"Source '{self.name}': at least one pii_column is required")
        if self.customer_id_column in self.pii_columns:
            raise ValueError(
                f"Source '{self.name}': customer_id_column '{self.customer_id_column}' "
                "cannot be a pii_column — it must remain readable for key lookup"
            )


@dataclass
class GdprOfficerConfig:
    """Top-level configuration."""

    customer_identifier: str = ""
    key_backend: str = "local"
    key_backend_config: dict[str, Any] = field(default_factory=dict)
    sources: list[SourceConfig] = field(default_factory=list)

    def get_source(self, name: str) -> SourceConfig:
        for source in self.sources:
            if source.name == name:
                return source
        available = [s.name for s in self.sources]
        raise KeyError(f"Source '{name}' not found. Available: {available}")

    def validate(self):
        if self.sources:
            for source in self.sources:
                source.validate()

    @classmethod
    def from_yaml(cls, path: str | Path) -> GdprOfficerConfig:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path) as f:
            raw = yaml.safe_load(f)

        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GdprOfficerConfig:
        sources = [
            SourceConfig(
                name=s["name"],
                customer_id_column=s.get(
                    "customer_id_column", data.get("customer_identifier", "")
                ),
                pii_columns=s.get("pii_columns", []),
                passthrough_columns=s.get("passthrough_columns"),
            )
            for s in data.get("sources", [])
        ]

        config = cls(
            customer_identifier=data.get("customer_identifier", ""),
            key_backend=data.get("key_backend", "local"),
            key_backend_config=data.get("key_backend_config", {}),
            sources=sources,
        )
        config.validate()
        return config
