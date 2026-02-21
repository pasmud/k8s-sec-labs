"""Command line interface for the offline manifest linter."""

import argparse
import json
from pathlib import Path

from .checks import scan
from .source import MAX_BYTES, Diagnostic


def scan_file(path: Path) -> list[Diagnostic]:
    def error(code, message):
        return [Diagnostic(1, 1, 1, (), code, message, True)]

    try:
        if not path.is_file():
            return error("INPUT_FILE", "Expected a readable regular file.")
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
    except OSError:
        return error("INPUT_FILE", "Could not read file.")
    if len(data) > MAX_BYTES:
        return error("INPUT_SIZE", f"File exceeds {MAX_BYTES} bytes.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return error("INPUT_ENCODING", "Expected UTF-8 text.")
    return scan(text)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Review rendered Kubernetes YAML files offline.")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="diagnostic format")
    parser.add_argument("files", metavar="FILE", nargs="+", help="local UTF-8 manifest file")
    args = parser.parse_args(argv)
    records = []
    status = 0
    for filename in args.files:
        for diagnostic in scan_file(Path(filename)):
            if args.format == "json":
                records.append({
                    "file": filename,
                    "document": diagnostic.document,
                    "line": diagnostic.line,
                    "column": diagnostic.column,
                    "path": diagnostic.path,
                    "level": "error" if diagnostic.error else "finding",
                    "code": diagnostic.code,
                    "message": diagnostic.message,
                })
            else:
                print(diagnostic.render(filename))
            status = max(status, 2 if diagnostic.error else 1)
    if args.format == "json":
        print(json.dumps(records))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
