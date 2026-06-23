"""Offline tests for the edge/air-gap data-feed catalog (otaverify.datafeeds).

No network: we only exercise catalog loading, listing, cache pathing, and the
air-gap snapshot export/import round-trip against a temp cache dir. Online
fetch/update/harvest are NOT exercised here (CI hits no external hosts).
"""

import json
import os

import pytest

from otaverify import datafeeds as df


def test_catalog_loads():
    cat = df.load_catalog()
    assert "feeds" in cat
    assert isinstance(cat["feeds"], list)
    assert len(cat["feeds"]) >= 5


def test_catalog_feeds_have_required_fields():
    for f in df.load_catalog()["feeds"]:
        assert "id" in f
        assert "url" in f
        assert f["url"].startswith("http")


def test_list_feeds_returns_all():
    feeds = df.list_feeds()
    assert len(feeds) == len(df.load_catalog()["feeds"])


def test_list_feeds_domain_filter():
    cat = df.load_catalog()
    domains = {f.get("domain") for f in cat["feeds"] if f.get("domain")}
    if domains:
        d = sorted(domains)[0]
        filtered = df.list_feeds(domain=d)
        assert filtered
        assert all(f.get("domain") == d for f in filtered)


def test_known_vuln_feeds_present():
    ids = {f["id"] for f in df.load_catalog()["feeds"]}
    # The catalog should carry the canonical keyless vuln feeds.
    assert ids & {"osv", "cisa-kev", "nvd-cve", "epss"}


def test_cache_dir_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "c"))
    d = df.cache_dir()
    assert d.exists()
    assert str(tmp_path) in str(d)


def test_cached_age_none_when_uncached(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "c2"))
    assert df.cached_age_hours("nonexistent-feed") is None


def test_snapshot_roundtrip(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(cache))
    d = df.cache_dir()
    # Seed a fake cached feed (no network).
    (d / "demo.data").write_bytes(b'{"hello":"world"}')
    (d / "demo.meta.json").write_text(json.dumps({"feed": "demo", "fetched_at": 1}))

    archive = tmp_path / "snap.tar.gz"
    n = df.snapshot_export(str(archive))
    assert n == 1
    assert archive.exists()

    # Import into a fresh cache dir.
    cache2 = tmp_path / "cache2"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(cache2))
    imported = df.snapshot_import(str(archive))
    assert imported == 1
    assert (df.cache_dir() / "demo.data").read_bytes() == b'{"hello":"world"}'


def test_get_offline_without_cache_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "empty"))
    with pytest.raises(FileNotFoundError):
        df.get("osv", offline=True)


def test_cli_list_runs(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "c3"))
    rc = df.main(["list"])
    assert rc == 0
    assert capsys.readouterr().out  # printed something
