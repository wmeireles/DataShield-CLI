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
