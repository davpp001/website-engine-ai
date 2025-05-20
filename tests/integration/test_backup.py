# Integrationstest für die Backup-Funktion des IONOS WP Managers
import pytest
from typer.testing import CliRunner
from src.ionos_wp_manager import app
import os

def test_backup_dry_run(tmp_path, monkeypatch):
    runner = CliRunner()
    # Setze HOME, damit keine echten Userdaten verwendet werden
    monkeypatch.setenv('HOME', str(tmp_path))
    # Lege Dummy-Konfig an
    config_dir = tmp_path / '.config' / 'ionos_wp_manager'
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / 'config.yml').write_text('base_domain: example.com\ns3_bucket: dummy-bucket\nlog_level: INFO\n')
    # Lege Dummy-Credentials an (verschlüsselt nicht nötig für Dry-Run)
    (config_dir / 'credentials').write_text('AWS_ACCESS_KEY_ID: dummy\nAWS_SECRET_ACCESS_KEY: dummy\n')
    # Teste Backup im Dry-Run
    result = runner.invoke(app, ['backup', '--dry-run', '--config', str(config_dir / 'config.yml')])
    assert result.exit_code == 0
    assert 'dry-run' in result.output
    assert 'Backup würde durchgeführt' in result.output
