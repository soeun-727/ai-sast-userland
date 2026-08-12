from __future__ import annotations

import hashlib
from bisect import bisect_right
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Node, Parser


C_LANGUAGE = Language(tree_sitter_c.language())
CPP_LANGUAGE = Language(tree_sitter_cpp.language())


@dataclass
class CodeChunk:
    chunk_id: str
    relative_path: str
    language: str
    symbol: str
    chunk_type: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    byte_size: int
    estimated_tokens: int
    has_parse_error: bool
    code: str

    def to_dict(self) -> dict:
        return asdict(self)


def detect_language(path: Path) -> str:
    suffix = path.suffix.lower()

    if suffix == ".c":
        return "c"

    if suffix in {".cc", ".cpp", ".cxx"}:
        return "cpp"

    raise ValueError(f"Unsupported source extension: {suffix}")


def create_parser(language: str) -> Parser:
    if language == "c":
        return Parser(C_LANGUAGE)

    if language == "cpp":
        return Parser(CPP_LANGUAGE)

    raise ValueError(f"Unsupported language: {language}")


def walk(node: Node) -> Iterator[Node]:
    stack = [node]

    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def find_identifier(node: Node, source: bytes) -> str:
    if node.type in {
        "identifier",
        "field_identifier",
        "type_identifier",
        "operator_name",
        "destructor_name",
    }:
        return source[node.start_byte:node.end_byte].decode(
            "utf-8",
            errors="replace",
        )

    for child in node.children:
        identifier = find_identifier(child, source)

        if identifier != "<anonymous>":
            return identifier

    return "<anonymous>"


def function_name(node: Node, source: bytes) -> str:
    declarator = node.child_by_field_name("declarator")

    if declarator is None:
        return "<anonymous>"

    return find_identifier(declarator, source)


def make_chunk_id(
    relative_path: str,
    symbol: str,
    start_byte: int,
    end_byte: int,
) -> str:
    raw_id = (
        f"{relative_path}:{symbol}:{start_byte}:{end_byte}"
    ).encode("utf-8")

    digest = hashlib.sha256(raw_id).hexdigest()[:16]
    return f"function-{digest}"


def estimate_tokens(code: str) -> int:
    # 초기 비교용 근삿값이다. 실제 모델 토큰 수는 추후 별도로 측정한다.
    return max(1, len(code) // 4)


def chunk_source_file(
    source_path: Path,
    repository_root: Path,
) -> tuple[list[CodeChunk], dict]:
    source_path = source_path.resolve()
    repository_root = repository_root.resolve()

    language = detect_language(source_path)
    parser = create_parser(language)

    source = source_path.read_bytes()
    tree = parser.parse(source)

    relative_path = source_path.relative_to(repository_root).as_posix()
    chunks: list[CodeChunk] = []
    newline_offsets = [
        index
        for index, byte in enumerate(source)
        if byte == ord("\n")
    ]

    for node in walk(tree.root_node):
        if node.type != "function_definition":
            continue

        symbol = function_name(node, source)
        code = source[node.start_byte:node.end_byte].decode(
            "utf-8",
            errors="replace",
        )

        start_line = bisect_right(
            newline_offsets,
            node.start_byte,
        ) + 1
        end_position = max(node.start_byte, node.end_byte - 1)
        end_line = bisect_right(
            newline_offsets,
            end_position,
        ) + 1

        chunks.append(
            CodeChunk(
                chunk_id=make_chunk_id(
                    relative_path,
                    symbol,
                    node.start_byte,
                    node.end_byte,
                ),
                relative_path=relative_path,
                language=language,
                symbol=symbol,
                chunk_type="function",
                start_line=start_line,
                end_line=end_line,
                start_byte=node.start_byte,
                end_byte=node.end_byte,
                byte_size=node.end_byte - node.start_byte,
                estimated_tokens=estimate_tokens(code),
                has_parse_error=node.has_error,
                code=code,
            )
        )

    manifest = {
        "relative_path": relative_path,
        "language": language,
        "source_bytes": len(source),
        "function_count": len(chunks),
        "root_has_parse_error": tree.root_node.has_error,
    }

    return chunks, manifest
