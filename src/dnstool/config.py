"""Configuration system for dnstool."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib  # type: ignore[import-not-found]
else:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[import-not-found, no-redef]

from dnstool.models import RecordType

# Default config directory
CONFIG_DIR = Path.home() / ".config" / "dnstool"
CONFIG_FILE = CONFIG_DIR / "config.toml"
TRACKED_DIR = CONFIG_DIR / "tracked"
BACKUPS_DIR = CONFIG_DIR / "backups"
HISTORY_DIR = CONFIG_DIR / "history"

# Default name servers
DEFAULT_NAMESERVERS = [
    "8.8.8.8",        # Google
    "1.1.1.1",        # Cloudflare
    "9.9.9.9",        # Quad9
    "208.67.222.222",  # OpenDNS
]

# Default record types to check/backup
DEFAULT_RECORD_TYPES = [
    RecordType.A,
    RecordType.AAAA,
    RecordType.MX,
    RecordType.TXT,
    RecordType.CNAME,
    RecordType.NS,
    RecordType.SOA,
    RecordType.SRV,
    RecordType.CAA,
    RecordType.PTR,
]

# Default compliance checks to run
DEFAULT_CHECKS = [
    "dmarc",
    "dkim",
    "spf",
    "dnssec",
    "mx_best_practices",
    "soa_best_practices",
    "ns_best_practices",
    "caa_best_practices",
    "txt_best_practices",
]


@dataclass
class NameserverConfig:
    """Configuration for a DNS nameserver."""

    ip: str
    label: str = ""
    timeout: float = 5.0


@dataclass
class BackupConfig:
    """Backup configuration for a domain."""

    record_types: list[RecordType] = field(default_factory=lambda: list(DEFAULT_RECORD_TYPES))
    max_snapshots: int = 50


@dataclass
class ScheduleConfig:
    """Schedule configuration for a domain."""

    enabled: bool = False
    cron: str = ""  # e.g. "*/6 * * * *"
    notify_on_change: bool = True


@dataclass
class DomainConfig:
    """Per-domain configuration."""

    nameservers: list[NameserverConfig] | None = None  # None = use global
    record_types: list[RecordType] | None = None  # None = use global
    checks: list[str] | None = None  # None = use global
    backup: BackupConfig = field(default_factory=BackupConfig)
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    tags: list[str] = field(default_factory=list)


@dataclass
class Config:
    """Main application configuration."""

    nameservers: list[NameserverConfig] = field(
        default_factory=lambda: [
            NameserverConfig(ip=ns) for ns in DEFAULT_NAMESERVERS
        ]
    )
    record_types: list[RecordType] = field(default_factory=lambda: list(DEFAULT_RECORD_TYPES))
    checks: list[str] = field(default_factory=lambda: list(DEFAULT_CHECKS))
    use_system_resolver: bool = True
    timeout: float = 5.0
    max_snapshots: int = 50
    domains: dict[str, DomainConfig] = field(default_factory=dict)

    def get_nameserver_ips(self) -> list[str]:
        """Get all configured nameserver IPs."""
        ips = [ns.ip for ns in self.nameservers]
        if self.use_system_resolver:
            # System resolver is handled by dnspython automatically
            pass
        return ips

    def get_record_types(self, domain: str | None = None) -> list[RecordType]:
        """Get record types for a domain, falling back to global config."""
        if domain and domain in self.domains:
            domain_cfg = self.domains[domain]
            if domain_cfg.record_types:
                return domain_cfg.record_types
        return self.record_types

    def get_checks(self, domain: str | None = None) -> list[str]:
        """Get checks for a domain, falling back to global config."""
        if domain and domain in self.domains:
            domain_cfg = self.domains[domain]
            if domain_cfg.checks:
                return domain_cfg.checks
        return self.checks


def _parse_nameservers(raw: list[dict[str, Any]]) -> list[NameserverConfig]:
    """Parse nameserver config from TOML data."""
    result = []
    for ns in raw:
        if isinstance(ns, str):
            result.append(NameserverConfig(ip=ns))
        elif isinstance(ns, dict):
            result.append(NameserverConfig(
                ip=ns["ip"],
                label=ns.get("label", ""),
                timeout=ns.get("timeout", 5.0),
            ))
    return result


def _parse_record_types(raw: list[str]) -> list[RecordType]:
    """Parse record type strings into RecordType enum."""
    return [RecordType(rt.upper()) for rt in raw]


def _parse_domain_config(raw: dict[str, Any]) -> DomainConfig:
    """Parse per-domain config from TOML data."""
    cfg = DomainConfig()

    if "nameservers" in raw:
        cfg.nameservers = _parse_nameservers(raw["nameservers"])

    if "record_types" in raw:
        cfg.record_types = _parse_record_types(raw["record_types"])

    if "checks" in raw:
        cfg.checks = raw["checks"]

    if "tags" in raw:
        cfg.tags = raw["tags"]

    if "backup" in raw:
        b = raw["backup"]
        if "record_types" in b:
            record_types = _parse_record_types(b["record_types"])
        else:
            record_types = list(DEFAULT_RECORD_TYPES)
        cfg.backup = BackupConfig(
            record_types=record_types,
            max_snapshots=b.get("max_snapshots", 50),
        )

    if "schedule" in raw:
        s = raw["schedule"]
        cfg.schedule = ScheduleConfig(
            enabled=s.get("enabled", False),
            cron=s.get("cron", ""),
            notify_on_change=s.get("notify_on_change", True),
        )

    return cfg


def load_config(config_path: Path | None = None) -> Config:
    """Load configuration from TOML file.

    Falls back to defaults if no config file exists.
    """
    path = config_path or CONFIG_FILE

    if not path.exists():
        return Config()

    with open(path, "rb") as f:
        data = tomllib.load(f)

    cfg = Config()

    # Global settings
    if "nameservers" in data:
        cfg.nameservers = _parse_nameservers(data["nameservers"])

    if "record_types" in data:
        cfg.record_types = _parse_record_types(data["record_types"])

    if "checks" in data:
        cfg.checks = data["checks"]

    if "use_system_resolver" in data:
        cfg.use_system_resolver = data["use_system_resolver"]

    if "timeout" in data:
        cfg.timeout = data["timeout"]

    if "max_snapshots" in data:
        cfg.max_snapshots = data["max_snapshots"]

    # Per-domain settings
    if "domains" in data:
        for domain, domain_data in data["domains"].items():
            cfg.domains[domain] = _parse_domain_config(domain_data)

    return cfg


def save_default_config(config_path: Path | None = None) -> Path:
    """Save a default config file to disk.

    Returns the path to the saved config.
    """
    path = config_path or CONFIG_FILE
    path.parent.mkdir(parents=True, exist_ok=True)

    content = """# dnstool configuration

# DNS nameservers to query
nameservers = [
    { ip = "8.8.8.8", label = "Google" },
    { ip = "1.1.1.1", label = "Cloudflare" },
    { ip = "9.9.9.9", label = "Quad9" },
    { ip = "208.67.222.222", label = "OpenDNS" },
]

# Include system resolver in queries
use_system_resolver = true

# Query timeout in seconds
timeout = 5.0

# Record types to check by default
record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "SRV", "CAA", "PTR"]

# Compliance checks to run
checks = [
    "dmarc",
    "dkim",
    "spf",
    "dnssec",
    "mx_best_practices",
    "soa_best_practices",
    "ns_best_practices",
    "caa_best_practices",
    "txt_best_practices",
]

# Max snapshots to keep per domain
max_snapshots = 50

# Per-domain overrides (optional)
# [domains.example.com]
# record_types = ["A", "AAAA", "MX", "TXT"]
# checks = ["dmarc", "dkim", "spf"]
# tags = ["production", "email"]
#
# [domains.example.com.schedule]
# enabled = true
# cron = "*/6 * * * *"
# notify_on_change = true
"""

    with open(path, "w") as f:
        f.write(content)

    return path


def ensure_dirs() -> None:
    """Ensure all required directories exist."""
    for d in [CONFIG_DIR, TRACKED_DIR, BACKUPS_DIR, HISTORY_DIR]:
        d.mkdir(parents=True, exist_ok=True)
