"""Tests for Cross-Platform CLI & Eye of Horus Banner."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from godseye.cli.main import app
from godseye.core.banner import EYE_OF_HORUS_GLYPH, get_eye_of_horus_banner

runner = CliRunner()


def test_eye_of_horus_banner_contains_symbol() -> None:
    banner_str = get_eye_of_horus_banner()
    assert EYE_OF_HORUS_GLYPH in banner_str
    assert "G O D ' S   E Y E" in banner_str


def test_cli_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_file = tmp_path / "cli_test.db"
    monkeypatch.setenv("GODSEYE_DB_PATH", str(db_file))
    from godseye.core.config import get_settings

    get_settings.cache_clear()

    # 1. Default invocation renders Eye of Horus banner & command table
    res_root = runner.invoke(app, [])
    assert res_root.exit_code == 0
    assert "GOD'S EYE" in res_root.stdout

    # 2. Sources command
    res_sources = runner.invoke(app, ["sources", "--region", "brasil"])
    assert res_sources.exit_code == 0
    assert "BRASIL" in res_sources.stdout
    assert "Receita" in res_sources.stdout

    # 3. Scan command with dossier export
    out_md = tmp_path / "dossier.md"
    res_scan = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--depth",
            "1",
            "--sources",
            "rdap,dns_doh",
            "--output",
            str(out_md),
            "--format",
            "md",
        ],
    )
    assert res_scan.exit_code == 0
    assert out_md.exists()
    assert "God's Eye OSINT Investigative Dossier" in out_md.read_text(encoding="utf-8")

    # 4. Cases & Audit commands
    res_cases = runner.invoke(app, ["cases"])
    assert res_cases.exit_code == 0

    res_audit = runner.invoke(app, ["audit"])
    assert res_audit.exit_code == 0
    assert "case.created" in res_audit.stdout

    # 5. Zero-Config Doctor command
    res_doc = runner.invoke(app, ["doctor"])
    assert res_doc.exit_code == 0
    assert "READY" in res_doc.stdout
