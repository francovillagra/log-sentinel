"""TLS hacia la base: por defecto cifra sin verificar (con aviso); verify-ca / verify-full verifican de verdad."""
import logging
import shutil
import ssl
import subprocess

import pytest

from api.services.db import build_ssl_context


def test_default_mode_encrypts_without_verifying_and_warns(monkeypatch, caplog):
    monkeypatch.delenv("DATABASE_SSL_MODE", raising=False)
    with caplog.at_level(logging.WARNING):
        ctx = build_ssl_context()
    assert ctx.verify_mode == ssl.CERT_NONE and ctx.check_hostname is False
    assert "no se verifica" in caplog.text


def test_unknown_mode_is_refused(monkeypatch):
    monkeypatch.setenv("DATABASE_SSL_MODE", "prefer")
    with pytest.raises(RuntimeError, match="DATABASE_SSL_MODE"):
        build_ssl_context()


def test_disable_mode_turns_tls_off_with_a_warning(monkeypatch, caplog):
    monkeypatch.setenv("DATABASE_SSL_MODE", "disable")
    with caplog.at_level(logging.WARNING):
        assert build_ssl_context() == "disable"
    assert "SIN cifrar" in caplog.text


@pytest.mark.parametrize("mode", ["verify-ca", "verify-full"])
def test_verifying_modes_need_the_ca(monkeypatch, mode):
    monkeypatch.setenv("DATABASE_SSL_MODE", mode)
    monkeypatch.delenv("DATABASE_SSL_CA", raising=False)
    with pytest.raises(RuntimeError, match="DATABASE_SSL_CA"):
        build_ssl_context()


@pytest.fixture(scope="module")
def ca_pem(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("hace falta openssl para generar una CA de prueba")
    folder = tmp_path_factory.mktemp("ca")
    key, crt = folder / "ca.key", folder / "ca.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
         "-days", "2", "-subj", "/CN=Test CA", "-addext", "basicConstraints=critical,CA:TRUE"],
        check=True, capture_output=True,
    )
    return crt


def test_verify_full_with_a_ca_file_checks_certificate_and_hostname(monkeypatch, ca_pem):
    monkeypatch.setenv("DATABASE_SSL_MODE", "verify-full")
    monkeypatch.setenv("DATABASE_SSL_CA", str(ca_pem))
    ctx = build_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    assert len(ctx.get_ca_certs()) == 1


def test_verify_ca_accepts_the_pem_text_and_skips_the_hostname(monkeypatch, ca_pem):
    monkeypatch.setenv("DATABASE_SSL_MODE", "verify-ca")
    monkeypatch.setenv("DATABASE_SSL_CA", ca_pem.read_text())
    ctx = build_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is False
    assert len(ctx.get_ca_certs()) == 1


def test_a_missing_ca_file_fails_loudly(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_SSL_MODE", "verify-full")
    monkeypatch.setenv("DATABASE_SSL_CA", str(tmp_path / "no-existe.pem"))
    with pytest.raises(OSError):
        build_ssl_context()
