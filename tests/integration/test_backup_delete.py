# Integrationstest für Backup und Delete-Flow
import pytest
from typer.testing import CliRunner
from src.ionos_wp_manager import app
import os

def test_backup_and_delete_dry_run(tmp_path, monkeypatch):
    runner = CliRunner()
    monkeypatch.setenv('HOME', str(tmp_path))
    # Dummy-Konfig und -Credentials
    config_dir = tmp_path / '.config' / 'ionos_wp_manager'
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / 'config.yml').write_text('base_domain: example.com\ns3_bucket: dummy-bucket\ns3_endpoint: https://dummy-s3\nionos_server_id: dummy-server\nionos_volume_id: dummy-vol\nlog_level: INFO\n')
    (config_dir / 'credentials').write_text('AWS_ACCESS_KEY_ID: dummy\nAWS_SECRET_ACCESS_KEY: dummy\nS3_ENDPOINT: https://dummy-s3\n')
    # Backup Dry-Run
    result = runner.invoke(app, ['backup', '--dry-run', '--config', str(config_dir / 'config.yml')])
    assert result.exit_code == 0
    assert 'dry-run' in result.output
    assert 'Backup würde durchgeführt' in result.output
    # Delete Dry-Run
    result2 = runner.invoke(app, ['delete-site', 'testsite', '--dry-run', '--config', str(config_dir / 'config.yml')])
    assert result2.exit_code == 0
    assert 'dry-run' in result2.output
    assert 'würde gelöscht' in result2.output
