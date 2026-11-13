"""Generación de las credenciales de la demo: tienen que pasar la misma validación que la API aplica al arrancar."""
import stat

import pytest

from api.config import require_secret, validate_admin_password
from demo.console import make_secrets

FILES = ("postgres_password", "jwt_secret", "ingest_api_key", "admin_email", "admin_password")


@pytest.fixture
def directory(tmp_path, monkeypatch):
    monkeypatch.setattr(make_secrets, "DIRECTORY", tmp_path / "creds")
    return tmp_path / "creds"


def test_it_creates_every_credential_and_the_api_accepts_them(directory, monkeypatch, capsys):
    assert make_secrets.main() == 0
    values = {name: (directory / name).read_text().strip() for name in FILES}
    assert all(values.values())

    monkeypatch.setenv("JWT_SECRET", values["jwt_secret"])
    monkeypatch.setenv("INGEST_API_KEY", values["ingest_api_key"])
    assert require_secret("JWT_SECRET") == values["jwt_secret"]
    assert require_secret("INGEST_API_KEY") == values["ingest_api_key"]
    assert validate_admin_password(values["admin_password"]) == values["admin_password"]
    assert values["jwt_secret"] != values["ingest_api_key"]
    assert len(values["postgres_password"]) == 48 and set(values["postgres_password"]) <= set("0123456789abcdef")

    shown = capsys.readouterr().out
    assert not any(v in shown for k, v in values.items() if k != "admin_email"), "no imprime ninguna credencial"


def test_files_are_readable_by_the_other_containers_users(directory):
    make_secrets.main()
    for name in FILES:
        mode = stat.S_IMODE((directory / name).stat().st_mode)
        assert mode == 0o644, f"{name}: la base, la API y la consola leen con usuarios distintos"


def test_a_second_run_keeps_what_exists(directory, capsys):
    make_secrets.main()
    first = {name: (directory / name).read_text() for name in FILES}
    capsys.readouterr()
    make_secrets.main()
    assert {name: (directory / name).read_text() for name in FILES} == first
    assert "ya existían" in capsys.readouterr().out


def test_an_empty_file_is_filled_in_and_the_rest_is_kept(directory):
    make_secrets.main()
    kept = (directory / "jwt_secret").read_text()
    (directory / "admin_password").write_text("")
    make_secrets.main()
    assert (directory / "admin_password").read_text().strip()
    assert (directory / "jwt_secret").read_text() == kept


def test_the_passphrase_is_easy_to_dictate_and_strong_enough_for_the_api():
    for _ in range(200):
        phrase = make_secrets.new_passphrase()
        *words, digits = phrase.split("-")
        assert len(words) == 3 and len(set(words)) == 3 and digits.isdigit() and len(digits) == 2
        assert all(w in make_secrets.WORDS and w.isascii() for w in words)
        validate_admin_password(phrase)


def test_the_word_list_has_no_duplicates_nor_example_markers():
    assert len(set(make_secrets.WORDS)) == len(make_secrets.WORDS) >= 100
    assert not [w for w in make_secrets.WORDS for m in make_secrets.EXAMPLE_MARKERS if m in w]
