# Integration-Test-Beispiel für ionos_wp_manager
import pytest
from typer.testing import CliRunner
from src.ionos_wp_manager import app

def test_init_dry_run(tmp_path, monkeypatch):
    runner = CliRunner()
    monkeypatch.setenv('HOME', str(tmp_path))
    result = runner.invoke(app, ['init', '--dry-run'])
    assert result.exit_code == 0
    assert 'dry-run' in result.output
