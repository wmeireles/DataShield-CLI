"""Command line interface for DataShield."""

import sys
from pathlib import Path
from typing import Annotated, cast

import typer
from rich.console import Console
from rich.table import Table

from datashield.core.engine import create_engine
from datashield.core.pipeline import InputFormat, SanitizationPipeline
from datashield.core.vault import Vault
from datashield.utils.formatters import detect_format

app = typer.Typer(help="Detect and mask personal data locally.", no_args_is_help=True)
stderr = Console(stderr=True)


def _read_input(path: Path | None) -> str:
    return path.read_text(encoding="utf-8") if path else sys.stdin.read()


def _write_output(content: str, path: Path | None) -> None:
    if path:
        path.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)
        if content and not content.endswith("\n"):
            sys.stdout.write("\n")


def _resolve_format(content: str, path: Path | None, forced: str | None) -> InputFormat:
    result = forced or detect_format(content, str(path or ""))
    if result not in {"json", "csv", "text"}:
        raise typer.BadParameter("format must be json, csv, or text")
    return cast(InputFormat, result)


@app.command()
def clean(
    input_path: Annotated[
        Path | None, typer.Argument(help="Input file; reads stdin when omitted.")
    ] = None,
    output: Annotated[Path | None, typer.Option("-o", "--output")] = None,
    format: Annotated[str | None, typer.Option("-f", "--format")] = None,
    export_vault: Annotated[
        Path | None, typer.Option(help="Write encrypted token mappings.")
    ] = None,
    vault_key: Annotated[
        Path | None, typer.Option(help="Read or create the separate Fernet key file.")
    ] = None,
) -> None:
    """Mask detected PII and optionally export its encrypted mapping."""
    try:
        content = _read_input(input_path)
        input_format = _resolve_format(content, input_path, format)
        engine = create_engine()
        outcome = SanitizationPipeline(engine).process(content, input_format=input_format)
        if export_vault:
            if vault_key is None:
                raise typer.BadParameter("--vault-key is required with --export-vault")
            key = vault_key.read_bytes() if vault_key.exists() else Vault.generate_key()
            if not vault_key.exists():
                vault_key.write_bytes(key)
            export_vault.write_bytes(engine.vault.export_encrypted(key))
        _write_output(outcome.content, output)
        if outcome.stats:
            stderr.print(
                "Detected: "
                + ", ".join(f"{name.upper()}: {count}" for name, count in outcome.stats.items())
            )
    except (OSError, ValueError) as exc:
        stderr.print(f"Error: {exc}")
        raise typer.Exit(code=2) from exc


@app.command()
def detect(
    input_path: Annotated[
        Path | None, typer.Argument(help="Input file; reads stdin when omitted.")
    ] = None,
    format: Annotated[str | None, typer.Option("-f", "--format")] = None,
) -> None:
    """Report detected PII without changing the input."""
    try:
        content = _read_input(input_path)
        input_format = _resolve_format(content, input_path, format)
        outcome = SanitizationPipeline().process(content, input_format=input_format)
        table = Table("Type", "Original", "Position")
        for item in outcome.detections:
            table.add_row(item.detector_name, item.original, f"{item.start}:{item.end}")
        stderr.print(table)
        stderr.print(f"Total detections: {len(outcome.detections)}")
    except (OSError, ValueError) as exc:
        stderr.print(f"Error: {exc}")
        raise typer.Exit(code=2) from exc


@app.command()
def restore(
    vault: Annotated[Path, typer.Option("-v", "--vault", help="Encrypted vault file.")],
    vault_key: Annotated[Path, typer.Option("--vault-key", help="Separate Fernet key file.")],
    input_path: Annotated[
        Path | None, typer.Argument(help="Sanitized input; reads stdin when omitted.")
    ] = None,
    output: Annotated[Path | None, typer.Option("-o", "--output")] = None,
) -> None:
    """Restore original values using a vault and its separate key."""
    try:
        mappings = Vault()
        mappings.import_encrypted(vault.read_bytes(), vault_key.read_bytes())
        content = _read_input(input_path)
        engine = create_engine()
        restored = engine.desanitize(content, mappings)
        _write_output(restored, output)
    except (OSError, ValueError) as exc:
        stderr.print(f"Error: {exc}")
        raise typer.Exit(code=2) from exc


if __name__ == "__main__":
    app()
