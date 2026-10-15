"""Test suite for domain ownership and consent gating."""
from pathlib import Path
import json
import pytest
from typer.testing import CliRunner
from unittest.mock import patch

from veylance.cli import app
from veylance.config import TERMS_VERSION
from veylance.ui.consent import has_consent, record_consent

runner = CliRunner()


def test_no_flag_no_saved_consent_simulated_no(tmp_path: Path, monkeypatch):
    """no flag + no saved consent + simulated 'no' answer -> scan does NOT proceed."""
    fake_consent = tmp_path / "consent.json"
    fake_audit = tmp_path / "audit.log"
    monkeypatch.setattr("veylance.config.CONSENT_FILE", fake_consent)
    monkeypatch.setattr("veylance.ui.consent.CONSENT_FILE", fake_consent)
    monkeypatch.setattr("veylance.config.AUDIT_LOG_FILE", fake_audit)

    # Input: 'n' to authorization prompt
    res = runner.invoke(app, ["scan", "https://example.com", "-m", "headers"], input="n\n")
    assert res.exit_code == 0 or res.exit_code == 1
    assert "Cancelled" in res.output or "required" in res.output
    # Scan should not have run
    assert "Discovered Count" not in res.output


def test_no_flag_no_saved_consent_simulated_yes(tmp_path: Path, monkeypatch):
    """no flag + no saved consent + simulated 'yes' answer -> scan proceeds and consent is optionally saved."""
    fake_consent = tmp_path / "consent.json"
    fake_audit = tmp_path / "audit.log"
    monkeypatch.setattr("veylance.config.CONSENT_FILE", fake_consent)
    monkeypatch.setattr("veylance.ui.consent.CONSENT_FILE", fake_consent)
    monkeypatch.setattr("veylance.config.AUDIT_LOG_FILE", fake_audit)

    # Input: 'y' to authorization, 'y' to save for future
    res = runner.invoke(app, ["scan", "https://example.com", "-m", "headers"], input="y\ny\n")
    assert res.exit_code == 0
    # Must have prompted
    assert "explicit written authorization" in res.output or "authorized to scan" in res.output
    # Consent must now be saved for example.com
    assert has_consent(domain="example.com", consent_path=fake_consent)


def test_saved_consent_proceeds_without_prompt(tmp_path: Path, monkeypatch):
    """Prior saved consent for exact domain proceeds without prompt."""
    fake_consent = tmp_path / "consent.json"
    fake_audit = tmp_path / "audit.log"
    monkeypatch.setattr("veylance.config.CONSENT_FILE", fake_consent)
    monkeypatch.setattr("veylance.ui.consent.CONSENT_FILE", fake_consent)
    monkeypatch.setattr("veylance.config.AUDIT_LOG_FILE", fake_audit)

    record_consent(domain="example.com", consent_path=fake_consent)

    # No input provided - if it prompted, it would fail or EOF
    res = runner.invoke(app, ["scan", "https://example.com", "-m", "headers"])
    assert res.exit_code == 0
    # Should not have prompted
    assert "Do you own 'example.com'" not in res.output


def test_yes_flag_proceeds_without_prompt(tmp_path: Path, monkeypatch):
    """--yes proceeds without any prompt."""
    fake_consent = tmp_path / "consent.json"
    monkeypatch.setattr("veylance.config.CONSENT_FILE", fake_consent)
    monkeypatch.setattr("veylance.ui.consent.CONSENT_FILE", fake_consent)

    res = runner.invoke(app, ["scan", "https://example.com", "--yes", "-m", "headers"])
    assert res.exit_code == 0
    assert "Do you own" not in res.output


def test_valid_i_own_this_proceeds_without_prompt(tmp_path: Path, monkeypatch):
    """Valid --i-own-this proceeds without prompt."""
    fake_consent = tmp_path / "consent.json"
    monkeypatch.setattr("veylance.config.CONSENT_FILE", fake_consent)
    monkeypatch.setattr("veylance.ui.consent.CONSENT_FILE", fake_consent)

    res = runner.invoke(app, ["scan", "https://example.com", "--i-own-this", "example.com", "-m", "headers"])
    assert res.exit_code == 0
    assert "Do you own" not in res.output


def test_mismatched_i_own_this_blocked(tmp_path: Path, monkeypatch):
    """Mismatched --i-own-this blocked regardless of input."""
    fake_consent = tmp_path / "consent.json"
    monkeypatch.setattr("veylance.config.CONSENT_FILE", fake_consent)
    monkeypatch.setattr("veylance.ui.consent.CONSENT_FILE", fake_consent)

    res = runner.invoke(app, ["scan", "https://example.com", "--i-own-this", "evil.com", "-m", "headers"], input="y\ny\n")
    assert res.exit_code != 0
    assert "Domain mismatch" in res.output
