import os
import subprocess
import sys

from typer.testing import CliRunner
from veylance.cli import app

runner = CliRunner()


def test_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0
    assert "Veylance" in r.stdout


def test_modules_list():
    r = runner.invoke(app, ["modules-list"])
    assert r.exit_code == 0


def test_help_windows_encoding():
    env = os.environ.copy()
    env.pop("PYTHONIOENCODING", None)
    env.pop("PYTHONUTF8", None)
    result = subprocess.run(
        [sys.executable, "-m", "veylance", "--help"],
        env=env,
        capture_output=True,
        encoding="utf-8",
    )
    assert result.returncode == 0
    assert "Interactive website security self-audit tool" in result.stdout


def test_cli_scan_direct_call_no_optioninfo_error():
    from veylance.cli import scan as scan_cmd
    import typer
    import pytest

    # Calling scan_cmd directly without specifying i_own_this should not crash with OptionInfo AttributeError
    try:
        scan_cmd(
            url="https://example.com",
            modules="headers",
            concurrency=1,
            rate=1,
            max_pages=1,
            yes=True,
        )
    except typer.Exit:
        pass
    except AttributeError as e:
        pytest.fail(f"Raised OptionInfo AttributeError: {e}")