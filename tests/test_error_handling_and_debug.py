"""Unit tests for error handling pipeline, per-module timeout, and --debug flag."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from veylance.cli import app
from veylance.core.engine import ScanEngine
from veylance.core.target import Target


class HangingModule:
    name = "hanging_module"
    description = "Simulates a hanging or stalled check"
    requires_crawl = False

    def __init__(self, target, session, ctx):
        pass

    async def run(self):
        raise asyncio.TimeoutError()


class CrashingModule:
    name = "crashing_module"
    description = "Simulates an unexpected module crash"
    requires_crawl = False

    def __init__(self, target, session, ctx):
        pass

    async def run(self):
        raise ConnectionResetError("Simulated socket connection reset")


@pytest.mark.asyncio
async def test_engine_gracefully_handles_hanging_and_crashing_modules(tmp_path):
    target = Target("https://example.com")

    with patch.dict("veylance.modules.ALL_MODULES", {
        "hanging_test": HangingModule,
        "crashing_test": CrashingModule,
    }, clear=False):
        engine = ScanEngine(
            target=target,
            modules=["hanging_test", "crashing_test"],
            timeout=1,
        )
        result = await engine.run()


        assert len(result.errors) == 2
        assert any("hanging_test: module skipped: execution timed out" in err for err in result.errors)
        assert any("crashing_test: module skipped: ConnectionResetError" in err for err in result.errors)
        # Verify engine completed cleanly without raw traceback
        assert result.findings == []


def test_cli_debug_flag_vs_default_error_output():
    runner = CliRunner()

    # Pass an invalid target to trigger an error
    # Normal execution (no --debug): should not reveal raw Python tracebacks
    res_normal = runner.invoke(app, ["scan", "http://invalid-target:99999", "--yes"])
    assert res_normal.exit_code != 0
    assert "Traceback (most recent call last)" not in res_normal.stdout

    # With --debug: should run with debug logger enabled
    res_debug = runner.invoke(app, ["scan", "http://invalid-target:99999", "--yes", "--debug"])
    assert res_debug.exit_code != 0


def test_cli_max_concurrency_flag():
    runner = CliRunner()
    # Test that --max-concurrency flag is accepted by Typer without parse error
    res = runner.invoke(app, ["scan", "https://example.com", "--max-concurrency", "5", "-m", "headers", "--yes"])
    # Should run with max-concurrency option recognized
    assert res.exit_code == 0
