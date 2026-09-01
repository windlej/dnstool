"""Tests for the configuration system."""

from __future__ import annotations

from pathlib import Path

from dnstool.config import (
    _flatten_domain_configs,
    load_config,
)

TOML_WITH_DOTTED_DOMAINS = """\
[domains.example.com]
checks = ["dmarc", "dkim"]
tags = ["email"]

[domains.example.com.schedule]
enabled = true
cron = "*/6 * * * *"
notify_on_change = false

[domains."sub.my-domain.org".backup]
max_snapshots = 10
"""

TOML_INLINE_DOMAIN = """\
[domains]
"deep.example.co.uk" = { checks = ["spf"] }
"""


class TestFlattenDomainConfigs:
    def test_simple_dotted_key(self) -> None:
        data = {"example": {"com": {"checks": ["dmarc"], "schedule": {"enabled": True}}}}
        out = _flatten_domain_configs(data)
        assert "example.com" in out
        assert out["example.com"]["checks"] == ["dmarc"]

    def test_inline_table_domain_not_doubleparsed(self) -> None:
        data = {"deep.example.co.uk": {"checks": ["spf"]}}
        out = _flatten_domain_configs(data)
        assert "deep.example.co.uk" in out

    def test_empty(self) -> None:
        assert _flatten_domain_configs({}) == {}


class TestLoadConfigWithDottedDomains:
    def test_dotted_domain_parse(self, tmp_path: Path) -> None:
        p = tmp_path / "config.toml"
        p.write_text(TOML_WITH_DOTTED_DOMAINS)
        cfg = load_config(p)
        assert "example.com" in cfg.domains
        dc = cfg.domains["example.com"]
        assert dc.checks == ["dmarc", "dkim"]
        assert dc.schedule.enabled is True
        assert dc.schedule.cron == "*/6 * * * *"
        assert dc.schedule.notify_on_change is False

    def test_multi_label_subdomain(self, tmp_path: Path) -> None:
        p = tmp_path / "config.toml"
        p.write_text(TOML_WITH_DOTTED_DOMAINS)
        cfg = load_config(p)
        assert "sub.my-domain.org" in cfg.domains
        assert cfg.domains["sub.my-domain.org"].backup.max_snapshots == 10

    def test_inline_domain_table(self, tmp_path: Path) -> None:
        p = tmp_path / "config.toml"
        p.write_text(TOML_INLINE_DOMAIN)
        cfg = load_config(p)
        assert "deep.example.co.uk" in cfg.domains
        assert cfg.domains["deep.example.co.uk"].checks == ["spf"]

    def test_existing_quoted_domains_no_crash(self, tmp_path: Path) -> None:
        p = tmp_path / "config.toml"
        p.write_text('[domains."example.com"]\ntags = ["test"]\n')
        cfg = load_config(p)
        assert "example.com" in cfg.domains
        assert cfg.domains["example.com"].tags == ["test"]
