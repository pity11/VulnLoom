"""Trusted local LanguageAdapter boundary; target source is parsed, never executed."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol

from vulnloom.domain.models import SourceLocation

from .models import (
    BuildSystem,
    SourceLanguage,
    SourceReference,
    SourceReferenceKind,
    SourceSymbol,
    SourceSymbolKind,
)


@dataclass(frozen=True, slots=True)
class SourceDocument:
    path: str
    sha256: str
    text: str


@dataclass(frozen=True, slots=True)
class LanguageIndex:
    symbols: tuple[SourceSymbol, ...]
    references: tuple[SourceReference, ...]


class LanguageAdapter(Protocol):
    language: SourceLanguage
    version: str
    extensions: frozenset[str]

    def index(self, documents: tuple[SourceDocument, ...]) -> LanguageIndex: ...


def detect_build_systems(paths: tuple[str, ...]) -> tuple[BuildSystem, ...]:
    names = {PurePosixPath(path).name.casefold() for path in paths}
    detected = []
    if "pyproject.toml" in names:
        detected.append(BuildSystem.PYPROJECT)
    if any(name.startswith("requirements") and name.endswith(".txt") for name in names):
        detected.append(BuildSystem.REQUIREMENTS)
    if "package.json" in names:
        detected.append(BuildSystem.NPM)
    return tuple(detected)


class PythonLanguageAdapter:
    language = SourceLanguage.PYTHON
    version = "python-ast-index-v1"
    extensions = frozenset({".py"})

    def index(self, documents: tuple[SourceDocument, ...]) -> LanguageIndex:
        symbols: list[SourceSymbol] = []
        pending: list[tuple[str, str, str, int]] = []
        for document in documents:
            try:
                tree = ast.parse(document.text, filename=document.path)
            except SyntaxError:
                continue
            module = _module_name(document.path)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    qualified = f"{module}.{node.name}"
                    symbols.append(
                        SourceSymbol.create(
                            language=self.language,
                            qualified_name=qualified,
                            kind=(
                                SourceSymbolKind.CLASS
                                if isinstance(node, ast.ClassDef)
                                else SourceSymbolKind.FUNCTION
                            ),
                            location=SourceLocation(
                                path=document.path, line=node.lineno, symbol=qualified
                            ),
                        )
                    )
            for function in (
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                caller = f"{module}.{function.name}"
                for node in ast.walk(function):
                    if isinstance(node, ast.Call):
                        name = _python_call_name(node.func)
                        if name:
                            pending.append((document.path, caller, name, node.lineno))
        return _resolve(self.language, symbols, pending)


class JavaScriptLanguageAdapter:
    """Conservative JS/TS index used for bounded navigation, not vulnerability claims."""

    language = SourceLanguage.JAVASCRIPT
    version = "javascript-navigation-index-v1"
    extensions = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
    _function = re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|"
        r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
    )
    _class = re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)")
    _call = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")

    def index(self, documents: tuple[SourceDocument, ...]) -> LanguageIndex:
        symbols: list[SourceSymbol] = []
        pending: list[tuple[str, str, str, int]] = []
        for document in documents:
            module = _module_name(document.path)
            current = module
            for line_number, line in enumerate(document.text.splitlines(), 1):
                match = self._function.search(line)
                class_match = self._class.search(line)
                name = next((item for item in match.groups() if item), None) if match else None
                kind = SourceSymbolKind.FUNCTION
                if class_match:
                    name = class_match.group(1)
                    kind = SourceSymbolKind.CLASS
                if name:
                    current = f"{module}.{name}"
                    symbols.append(
                        SourceSymbol.create(
                            language=(
                                SourceLanguage.TYPESCRIPT
                                if PurePosixPath(document.path).suffix in {".ts", ".tsx"}
                                else self.language
                            ),
                            qualified_name=current,
                            kind=kind,
                            location=SourceLocation(
                                path=document.path, line=line_number, symbol=current
                            ),
                        )
                    )
                for call in self._call.finditer(line):
                    target = call.group(1)
                    if target not in {"if", "for", "while", "switch", "function"}:
                        pending.append((document.path, current, target, line_number))
        return _resolve(self.language, symbols, pending)


def _module_name(path: str) -> str:
    value = PurePosixPath(path).with_suffix("").as_posix().replace("/", ".")
    return value.removesuffix(".__init__")


def _python_call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _python_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _resolve(
    language: SourceLanguage,
    symbols: list[SourceSymbol],
    pending: list[tuple[str, str, str, int]],
) -> LanguageIndex:
    by_tail: dict[str, list[SourceSymbol]] = {}
    for symbol in symbols:
        by_tail.setdefault(symbol.qualified_name.rsplit(".", 1)[-1], []).append(symbol)
    references = []
    for path, caller, target, line in pending:
        matches = by_tail.get(target.rsplit(".", 1)[-1], [])
        resolved = matches[0].symbol_id if len(matches) == 1 else None
        references.append(
            SourceReference.create(
                language=language,
                kind=SourceReferenceKind.CALL,
                source_symbol=caller,
                target_name=target,
                resolved_symbol_id=resolved,
                location=SourceLocation(path=path, line=line, symbol=caller),
            )
        )
    return LanguageIndex(
        symbols=tuple(sorted(symbols, key=lambda item: item.symbol_id)),
        references=tuple(sorted(references, key=lambda item: item.reference_id)),
    )

