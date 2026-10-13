from typer.testing import CliRunner
from sentinelscan.cli import app

runner = CliRunner()


def test_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0
    assert "SentinelScan" in r.stdout


def test_modules_list():
    r = runner.invoke(app, ["modules-list"])
    assert r.exit_code == 0