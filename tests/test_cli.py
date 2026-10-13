import os
import subprocess
import sys

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


def test_help_windows_encoding():
    env = os.environ.copy()
    env.pop("PYTHONIOENCODING", None)
    env.pop("PYTHONUTF8", None)
    result = subprocess.run(
        [sys.executable, "-m", "sentinelscan", "--help"],
        env=env,
        capture_output=True,
        encoding="utf-8",
    )
    assert result.returncode == 0
    assert "Interactive website security self-audit tool" in result.stdout