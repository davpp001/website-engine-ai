# Unit-Test-Beispiel für ionos_wp_manager
import pytest
from typer.testing import CliRunner
from src.ionos_wp_manager import app

def test_help():
    runner = CliRunner()
    result = runner.invoke(app, ['--help'])
    assert result.exit_code == 0
    assert 'Commands' in result.output
