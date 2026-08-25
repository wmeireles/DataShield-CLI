"""DataShield CLI - Main entry point."""

import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from datashield.core.engine import SanitizeResult, create_engine
from datashield.core.vault import Vault
from datashield.utils.formatters import detect_format, parse_content, serialize_content

app = typer.Typer(
    name="datashield",
    help="Local, high-performance PII detection and sanitization for LLM context",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


def read_input(file_path: Path | None) -> str:
    """Read input from file or stdin."""
    if file_path:
        return file_path.read_text(encoding="utf-8")
    return sys.stdin.read()


def write_output(content: str, file_path: Path | None) -> None:
    """Write output to file or stdout."""
    if file_path:
        file_path.write_text(content, encoding="utf-8")
    else:
        console.print(content)


@app.command()
def clean(
    file_path: Path | None = typer.Argument(  # noqa: B008
        None,
        help="Input file path (reads from stdin if omitted)",
        exists=True,
        readable=True,
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "-o",
        "--output",
        help="Output file path (writes to stdout if omitted)",
    ),
    show_diff: bool = typer.Option(
        False,
        "--show-diff",
        help="Show comparison table of original vs sanitized",
    ),
    format: str | None = typer.Option(
        None,
        "-f",
        "--format",
        help="Force input format: json, csv, text",
    ),
    keep_format: bool = typer.Option(
        True,
        "--keep-format/--no-keep-format",
        help="Preserve input format in output",
    ),
) -> None:
    """Sanitize PII from input data."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Reading input...", total=None)

        input_text = read_input(file_path)
        if not input_text.strip():
            console.print("[yellow]Warning:[/yellow] Empty input")
            return

        fmt = format or detect_format(input_text, file_path.name if file_path else "")
        progress.update(task, description="Parsing content...")

        data = parse_content(input_text, file_path.name if file_path else "")

        progress.update(task, description="Sanitizing PII...")

        engine = create_engine()
        if isinstance(data, str):
            result = engine.sanitize(data)
            sanitized = result.sanitized_text
        elif isinstance(data, dict):
            sanitized_dict = engine.sanitize_dict(data)
            sanitized = (
                serialize_content(sanitized_dict, fmt)
                if keep_format
                else str(sanitized_dict)
            )
        elif isinstance(data, list):
            sanitized_list: list[Any] = []
            for item in data:
                if isinstance(item, dict):
                    sanitized_list.append(engine.sanitize_dict(item))
                elif isinstance(item, str):
                    sanitized_list.append(engine.sanitize(item).sanitized_text)
                else:
                    sanitized_list.append(item)
            sanitized = (
                serialize_content(sanitized_list, fmt)
                if keep_format
                else str(sanitized_list)
            )
        else:
            sanitized = str(data)

        progress.update(task, description="Complete!")

    if show_diff and isinstance(data, str):
        show_comparison(data, sanitized, engine.vault)

    write_output(sanitized, output)

    if output:
        console.print(f"[green]✓[/green] Output written to {output}")

    print_summary(engine.vault)


@app.command()
def restore(
    file_path: Path | None = typer.Argument(  # noqa: B008
        None,
        help="Input file with tokens (reads from stdin if omitted)",
        exists=True,
        readable=True,
    ),
    vault_file: Path = typer.Option(  # noqa: B008
        ...,
        "-v",
        "--vault",
        help="Vault file exported during sanitization",
        exists=True,
        readable=True,
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "-o",
        "--output",
        help="Output file path (writes to stdout if omitted)",
    ),
) -> None:
    """Restore original PII from tokens using vault."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Reading input and vault...", total=None)

        input_text = read_input(file_path)
        vault_data = vault_file.read_bytes()

        progress.update(task, description="Restoring PII...")

        engine = create_engine()
        engine.vault.import_encrypted(vault_data)

        restored = engine.desanitize(input_text)

        progress.update(task, description="Complete!")

    write_output(restored, output)

    if output:
        console.print(f"[green]✓[/green] Output written to {output}")


@app.command()
def detect(
    file_path: Path | None = typer.Argument(  # noqa: B008
        None,
        help="Input file path (reads from stdin if omitted)",
        exists=True,
        readable=True,
    ),
    format: str | None = typer.Option(
        None,
        "-f",
        "--format",
        help="Force input format: json, csv, text",
    ),
) -> None:
    """Detect and report PII without sanitizing."""
    input_text = read_input(file_path)
    if not input_text.strip():
        console.print("[yellow]Warning:[/yellow] Empty input")
        return

    data = parse_content(input_text, file_path.name if file_path else "")

    engine = create_engine()

    if isinstance(data, str):
        sanitize_result = engine.sanitize(data)
        show_detection_report(sanitize_result, console)
    elif isinstance(data, dict):
        sanitized_dict = engine.sanitize_dict(data)
        console.print(f"[green]Detected PII in {len(sanitized_dict)} fields[/green]")
    elif isinstance(data, list):
        console.print(f"[green]Detected PII in {len(data)} records[/green]")


def show_comparison(original: str, sanitized: str, vault: Vault) -> None:
    """Show side-by-side comparison of original and sanitized text."""
    table = Table(title="PII Sanitization Comparison")
    table.add_column("Original", style="red")
    table.add_column("Sanitized", style="green")

    for token, mapping in vault.get_all_mappings().items():
        table.add_row(mapping.original, token)

    console.print(table)


def show_detection_report(result: SanitizeResult, console: Console) -> None:
    """Show detailed detection report."""
    if not result.detections:
        console.print("[green]No PII detected[/green]")
        return

    table = Table(title="PII Detection Report")
    table.add_column("Type", style="cyan")
    table.add_column("Original", style="red")
    table.add_column("Token", style="green")
    table.add_column("Position", style="yellow")
    table.add_column("Confidence", style="blue")

    for det in result.detections:
        table.add_row(
            det.detector_name.upper(),
            det.original,
            det.token,
            f"{det.start}-{det.end}",
            f"{det.confidence:.0%}"
        )

    console.print(table)


def print_summary(vault: Vault) -> None:
    """Print sanitization summary."""
    if not vault:
        return

    stats: dict[str, int] = {}
    for mapping in vault.get_all_mappings().values():
        stats[mapping.detector_name] = stats.get(mapping.detector_name, 0) + 1

    if not stats:
        console.print("[dim]No PII found[/dim]")
        return

    summary = " | ".join(f"{k.upper()}: {v}" for k, v in stats.items())
    console.print(Panel(summary, title="Sanitization Summary", border_style="green"))


def version_callback(value: bool) -> None:
    if value:
        from datashield import __version__
        console.print(f"DataShield CLI v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    """DataShield CLI - Offline PII sanitization for LLM context."""
    pass


if __name__ == "__main__":
    app()
