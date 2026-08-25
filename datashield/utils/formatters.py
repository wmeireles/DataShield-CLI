"""Formatters for parsing and reconstructing JSON/CSV data."""

import csv
import io
from typing import Any

import orjson


def parse_json(content: str) -> Any:
    """Parse JSON content.

    Args:
        content: JSON string

    Returns:
        Parsed Python object
    """
    return orjson.loads(content.encode())


def serialize_json(data: Any, indent: int = 2) -> str:
    """Serialize to JSON string.

    Args:
        data: Python object to serialize
        indent: Indentation spaces

    Returns:
        JSON string
    """
    return orjson.dumps(data, option=orjson.OPT_INDENT_2).decode()


def parse_csv(content: str, has_header: bool = True) -> list[dict[str, str]]:
    """Parse CSV content to list of dictionaries.

    Args:
        content: CSV string
        has_header: Whether first row is header

    Returns:
        List of row dictionaries
    """
    reader = csv.DictReader(io.StringIO(content))
    if not has_header:
        first_row = next(reader, None)
        if first_row:
            fieldnames = [f"col_{i}" for i in range(len(first_row))]
            reader = csv.DictReader(io.StringIO(content), fieldnames=fieldnames)
    return list(reader)


def serialize_csv(rows: list[dict[str, str]]) -> str:
    """Serialize list of dictionaries to CSV.

    Args:
        rows: List of row dictionaries

    Returns:
        CSV string
    """
    if not rows:
        return ""

    output = io.StringIO()
    fieldnames = list(rows[0].keys())
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def detect_format(content: str, filename: str = "") -> str:
    """Detect file format from content and/or filename.

    Args:
        content: File content
        filename: Optional filename for extension detection

    Returns:
        Format identifier: 'json', 'csv', or 'text'
    """
    if filename:
        ext = filename.lower().split(".")[-1]
        if ext in ("json",):
            return "json"
        if ext in ("csv",):
            return "csv"

    content = content.strip()
    if content.startswith(("{", "[")):
        try:
            orjson.loads(content.encode())
            return "json"
        except orjson.JSONDecodeError:
            pass

    if "\n" in content and ("," in content or "\t" in content):
        try:
            list(csv.reader(io.StringIO(content)))
            return "csv"
        except csv.Error:
            pass

    return "text"


def parse_content(content: str, filename: str = "") -> Any:
    """Parse content based on detected format.

    Args:
        content: File content
        filename: Optional filename

    Returns:
        Parsed data structure
    """
    fmt = detect_format(content, filename)
    if fmt == "json":
        return parse_json(content)
    if fmt == "csv":
        return parse_csv(content)
    return content


def serialize_content(data: Any, format: str) -> str:
    """Serialize data to specified format.

    Args:
        data: Data to serialize
        format: Target format ('json', 'csv', 'text')

    Returns:
        Serialized string
    """
    if format == "json":
        return serialize_json(data)
    if format == "csv":
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return serialize_csv(data)
        raise ValueError("CSV format requires list of dictionaries")
    return str(data)
