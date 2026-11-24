#!/usr/bin/env python3
"""
Generates generated/cli/i18n_embedded.hpp with compile-time translation arrays
indexed directly by kasumi::cli::i18n::Key.
"""

import argparse
import json
import re
import sys
from pathlib import Path

EXCEPTIONS = {
    "OperationDuration": "labels.duration",
    "HelpText": "help_text",
    "HelpTextAll": "help_text_all",
    "HelpGcRemoveWriter": "command_help.gc_remove-writer",
    "HelpGcRemoveBarrier": "command_help.gc_remove-barrier",
    "HelpResolveMissing": "command_help.resolve-missing",
    "OperationCancelledByUser": "sync.operation_cancelled_by_user",
    "PromptPassword": "prompts.password",
    "PromptConfirmPassword": "prompts.confirm_password",
    "PromptSalt": "prompts.salt",
    "PromptConfirmSalt": "prompts.confirm_salt",
    "PasswordsDoNotMatch": "prompts.passwords_do_not_match",
    "SaltsDoNotMatch": "prompts.salts_do_not_match",
}

PREFIXES = sorted(
    [
        ("Label", "labels."),
        ("Progress", "progress."),
        ("Diagnostics", "diagnostics."),
        ("Conflicts", "conflicts."),
        ("Ignore", "ignore."),
        ("ResolveMissing", "resolve_missing."),
        ("Help", "command_help."),
        ("Error", "errors."),
        ("Sync", "sync."),
        ("Plan", "sync.plan_"),
        ("Preview", "sync.preview_"),
        ("Status", "sync.status_"),
        ("Fsck", "fsck."),
        ("Gc", "gc."),
        ("Repack", "repack."),
        ("ManualWriterRemoval", "manual_writer_removal."),
        ("ManualBarrierRemoval", "manual_barrier_removal."),
        ("BarrierRemovalStage", "manual_barrier_removal.stage_"),
        ("BarrierRemovalMutation", "manual_barrier_removal.mutation_"),
        ("Remote", "remote."),
        ("Field", "fields."),
        ("Variant", "variants."),
        ("ContentState", "content_states."),
        ("MarkerState", "marker_states."),
        ("ObjectCategory", "object_categories."),
        ("OrphanKind", "orphan_kinds."),
        ("WriterState", "writer_states."),
        ("HealthState", "health_states."),
        ("Wizard", "wizard."),
        ("Daemon", "daemon."),
        ("Overview", "overview."),
    ],
    key=lambda item: -len(item[0]),
)


def key_to_json_path(key: str) -> str:
    if key in EXCEPTIONS:
        return EXCEPTIONS[key]
    for prefix, section in PREFIXES:
        if key.startswith(prefix):
            tail = key[len(prefix) :]
            snake = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", tail).lower()
            return section + snake
    return re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", key).lower()


def flatten_catalog(node: object, prefix: str = "") -> dict[str, str]:
    if isinstance(node, dict):
        result: dict[str, str] = {}
        for key, value in node.items():
            full = f"{prefix}.{key}" if prefix else str(key)
            result.update(flatten_catalog(value, full))
        return result
    if isinstance(node, str):
        return {prefix: node}
    raise ValueError(f"Unsupported JSON value for key {prefix!r}: {type(node).__name__}")


def parse_enum_keys(header_path: Path) -> list[str]:
    text = header_path.read_text(encoding="utf-8")
    match = re.search(r"enum class Key \{(.*?)\};", text, re.S)
    if not match:
        raise ValueError(f"Could not locate enum class Key in {header_path}")
    return [
        line.strip().rstrip(",")
        for line in match.group(1).splitlines()
        if line.strip() and not line.strip().startswith("//")
    ]


def cpp_string_literal(value: str) -> str:
    # Split long multiline values across adjacent string literals so every token
    # stays far below MSVC C2026 (16,380 bytes).
    def escape(text: str) -> str:
        out: list[str] = []
        for ch in text:
            if ch == "\\":
                out.append("\\\\")
            elif ch == '"':
                out.append('\\"')
            elif ch == "\n":
                out.append("\\n")
            elif ch == "\r":
                out.append("\\r")
            elif ch == "\t":
                out.append("\\t")
            else:
                out.append(ch)
        return "".join(out)

    parts = value.splitlines(keepends=True) or [""]
    chunks: list[str] = []
    current = ""
    for part in parts:
        if current and len((current + part).encode("utf-8")) > 1024:
            chunks.append(f'"{escape(current)}"')
            current = part
        else:
            current += part
    chunks.append(f'"{escape(current)}"')
    return " ".join(chunks)


def emit_array(name: str, values: list[str]) -> list[str]:
    lines = [f"inline constexpr std::array<std::string_view, {len(values)}> {name} = {{"]
    for value in values:
        lines.append(f"    {cpp_string_literal(value)},")
    lines.append("};")
    return lines


def generate_header(
    en_path: Path, pt_path: Path, header_path: Path, out_path: Path
) -> None:
    keys = parse_enum_keys(header_path)
    en_flat = flatten_catalog(json.loads(en_path.read_text(encoding="utf-8")))
    pt_flat = flatten_catalog(json.loads(pt_path.read_text(encoding="utf-8")))

    paths = [key_to_json_path(key) for key in keys]
    for catalog_name, flat in (("en.json", en_flat), ("pt-BR.json", pt_flat)):
        missing = [p for p in paths if not flat.get(p)]
        if missing:
            raise ValueError(f"Missing or empty keys in {catalog_name}: {missing[:5]}")
        extra = set(flat.keys()) - set(paths)
        if extra:
            raise ValueError(f"Unmapped keys in {catalog_name}: {sorted(extra)[:5]}")

    en_values = [en_flat[p] for p in paths]
    pt_values = [pt_flat[p] for p in paths]

    lines = [
        "// Generated by scripts/generate_i18n_embedded.py - DO NOT EDIT",
        "#ifndef KASUMI_CLI_I18N_EMBEDDED_HPP",
        "#define KASUMI_CLI_I18N_EMBEDDED_HPP",
        "",
        "#include <array>",
        "#include <cstddef>",
        "#include <string_view>",
        "",
        "namespace kasumi::cli::i18n::embedded {",
        "",
        f"inline constexpr std::size_t KEY_COUNT = {len(keys)};",
        "",
        *emit_array("EN_STRINGS", en_values),
        "",
        *emit_array("PT_BR_STRINGS", pt_values),
        "",
        "} // namespace kasumi::cli::i18n::embedded",
        "",
        "#endif // KASUMI_CLI_I18N_EMBEDDED_HPP",
        "",
    ]

    content = "\n".join(lines).encode("utf-8")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists() and out_path.read_bytes() == content:
        return
    out_path.write_bytes(content)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate embedded i18n tables.")
    parser.add_argument("--en", required=True, type=Path, help="Path to en.json")
    parser.add_argument("--pt", required=True, type=Path, help="Path to pt-BR.json")
    parser.add_argument(
        "--header",
        type=Path,
        default=None,
        help="Path to src/cli/i18n.hpp",
    )
    parser.add_argument("--output", required=True, type=Path, help="Output header path")
    args = parser.parse_args()

    header_path = args.header or (args.en.resolve().parent.parent / "src" / "cli" / "i18n.hpp")
    try:
        generate_header(args.en, args.pt, header_path, args.output)
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    sys.exit(main())
