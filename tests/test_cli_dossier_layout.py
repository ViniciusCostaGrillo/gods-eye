"""Tests for Consolidated Dossier Layout in CLI."""

from typer.testing import CliRunner
from godseye.cli.main import app

runner = CliRunner()


def test_scan_cli_renders_consolidated_card(tmp_path, monkeypatch):
    monkeypatch.setenv("GODSEYE_DB_PATH", str(tmp_path / "test_cli_dossier.db"))
    res = runner.invoke(app, ["scan", "00.000.000/0001-91", "--depth", "1", "--sources", "brasil_cnpj"])
    assert res.exit_code == 0
    assert "FICHA CONSOLIDADA DO ALVO" in res.stdout or "EMPRESAS" in res.stdout
    assert "Compliance Check CEIS/CNEP: Sem restrições" not in res.stdout
