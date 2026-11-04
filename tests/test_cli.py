"""End-to-end behavior tests for the command-line interface."""

import orjson
from typer.testing import CliRunner

from datashield.main import app

runner = CliRunner()


def test_clean_writes_only_sanitized_json_to_stdout():
    result = runner.invoke(
        app,
        ["clean", "--format", "json"],
        input='{"cpf":"111.444.777-35"}',
    )

    assert result.exit_code == 0
    assert orjson.loads(result.stdout) == {"cpf": "<CPF_1>"}
    assert "CPF: 1" in result.stderr


def test_clean_and_restore_use_separate_key_file(tmp_path):
    vault_path = tmp_path / "mapping.vault"
    key_path = tmp_path / "mapping.key"
    clean_result = runner.invoke(
        app,
        [
            "clean", "--format", "text", "--export-vault", str(vault_path),
            "--vault-key", str(key_path),
        ],
        input="CPF: 111.444.777-35",
    )

    assert clean_result.exit_code == 0
    assert clean_result.stdout.strip() == "CPF: <CPF_1>"
    assert vault_path.exists()
    assert key_path.exists()
    assert b"111.444.777-35" not in vault_path.read_bytes()

    restore_result = runner.invoke(
        app,
        ["restore", "--vault", str(vault_path), "--vault-key", str(key_path)],
        input=clean_result.stdout,
    )

    assert restore_result.exit_code == 0
    assert restore_result.stdout.strip() == "CPF: 111.444.777-35"
