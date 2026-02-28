"""Read a bounded YAML subset and retain positions for diagnostics."""

from dataclasses import dataclass
from math import isfinite
from typing import ClassVar

import yaml
from yaml.error import MarkedYAMLError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

MAX_BYTES = 1024 * 1024
MAX_DEPTH = 64
MAX_DOCUMENTS = 100
Path = tuple[str | int, ...]
Position = tuple[int, int]
STR = "tag:yaml.org,2002:str"
NULL = "tag:yaml.org,2002:null"


@dataclass(frozen=True)
class Diagnostic:
    document: int
    line: int
    column: int
    path: Path
    code: str
    message: str
    error: bool = False

    def render(self, filename: str) -> str:
        location = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}" for part in self.path
        )
        level = "error" if self.error else "finding"
        filename = "".join(c if c.isprintable() else ascii(c)[1:-1] for c in filename)
        return (
            f"{filename}:{self.line}:{self.column}: {level} {self.code} "
            f"[doc {self.document} {location}] {self.message}"
        )


@dataclass
class Document:
    number: int
    data: object
    positions: dict[Path, Position]

    def diagnostic(self, path: Path, code: str, message: str, *, error=False):
        nearest = path
        while nearest not in self.positions:
            nearest = nearest[:-1]
        line, column = self.positions[nearest]
        return Diagnostic(self.number, line, column, path, code, message, error)


class InputError(MarkedYAMLError):
    """A violation of the accepted YAML subset."""


def reject(message, mark):
    raise InputError(problem=message, problem_mark=mark)


class ManifestLoader(yaml.SafeLoader):
    depth = 0
    # Keep unquoted date-like values as strings instead of Python date objects.
    yaml_implicit_resolvers: ClassVar = {
        char: [(tag, regex) for tag, regex in rules if tag != "tag:yaml.org,2002:timestamp"]
        for char, rules in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def compose_document(self):
        start = self.peek_event()
        if start.version not in (None, (1, 1)):
            reject("Only the %YAML 1.1 version directive is supported.", start.start_mark)
        return super().compose_document()

    def compose_node(self, parent, index):
        event = self.peek_event()
        if isinstance(event, AliasEvent) or event.anchor is not None:
            reject("YAML anchors and aliases are not supported.", event.start_mark)
        if event.tag is not None:
            reject("Explicit YAML tags are not supported.", event.start_mark)
        if self.depth >= MAX_DEPTH:
            reject(f"YAML nesting exceeds {MAX_DEPTH} nodes.", event.start_mark)
        self.depth += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1


def position(mark) -> Position:
    return mark.line + 1, mark.column + 1


def convert(loader, node, path, positions, mark):
    positions[path] = position(mark)
    if isinstance(node, MappingNode):
        result = {}
        for key, value in node.value:
            if not isinstance(key, ScalarNode) or key.tag != STR:
                reject("Mapping keys must be strings; YAML merge keys are unsupported.", key.start_mark)
            if key.value in result:
                reject("Duplicate mapping key.", key.start_mark)
            result[key.value] = convert(loader, value, (*path, key.value), positions, key.start_mark)
        return result
    if isinstance(node, SequenceNode):
        return [
            convert(loader, item, (*path, index), positions, item.start_mark)
            for index, item in enumerate(node.value)
        ]
    try:
        value = loader.construct_object(node)
    except (ValueError, OverflowError, yaml.YAMLError):
        reject("Invalid or unsupported scalar.", node.start_mark)
    if isinstance(value, float) and not isfinite(value):
        reject("Non-finite numbers are not supported.", node.start_mark)
    return value


def load(text: str) -> tuple[list[Document], Diagnostic | None]:
    """Parse atomically: a YAML error invalidates the entire file."""
    loader = None
    number = 1
    documents = []
    try:
        loader = ManifestLoader(text)
        while loader.check_node():
            if number > MAX_DOCUMENTS:
                reject(f"YAML stream exceeds {MAX_DOCUMENTS} documents.", loader.peek_event().start_mark)
            node = loader.get_node()
            if not (isinstance(node, ScalarNode) and node.tag == NULL and node.value == ""):
                positions = {}
                data = convert(loader, node, (), positions, node.start_mark)
                documents.append(Document(number, data, positions))
            # Constructors cache by node identity. Release completed documents' nodes.
            loader.constructed_objects.clear()
            number += 1
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line, column = position(mark) if mark else (1, 1)
        message = exc.problem if isinstance(exc, InputError) else "Invalid YAML."
        return [], Diagnostic(number, line, column, (), "INPUT_YAML", message, True)
    finally:
        if loader is not None:
            loader.dispose()
    if not documents:
        return [], Diagnostic(1, 1, 1, (), "INPUT_EMPTY", "No manifest documents found.", True)
    return documents, None
