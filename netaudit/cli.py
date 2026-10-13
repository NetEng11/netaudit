"""Interfaz de línea de comandos."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report
from .parser import parse_config
from .rules import SEVERITIES, audit

EXTENSIONS = {".cfg", ".conf", ".txt"}


def collect_files(path: Path) -> "list[Path]":
    if path.is_file():
        return [path]
    return sorted(p for p in path.iterdir() if p.suffix.lower() in EXTENSIONS)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netaudit",
        description="Audita configuraciones de red (estilo Cisco IOS) y genera un informe.",
    )
    parser.add_argument("path", type=Path, help="Fichero de configuración o carpeta con varios")
    parser.add_argument("--format", choices=["text", "md", "json"], default="text")
    parser.add_argument("--output", type=Path, help="Guardar el informe en un fichero")
    parser.add_argument(
        "--fail-on", choices=[*SEVERITIES, "never"], default="high",
        help="Devuelve código de salida 1 si hay hallazgos de esta severidad o superior (por defecto: high)",
    )
    args = parser.parse_args(argv)

    if not args.path.exists():
        print(f"No existe la ruta: {args.path}", file=sys.stderr)
        return 2
    files = collect_files(args.path)
    if not files:
        print("No se encontraron ficheros de configuración (.cfg, .conf, .txt).", file=sys.stderr)
        return 2

    results = []
    for file in files:
        cfg = parse_config(file.read_text(encoding="utf-8", errors="replace"), source=file.name)
        results.append((cfg, audit(cfg)))

    renderer = {"text": report.to_text, "md": report.to_markdown, "json": report.to_json}[args.format]
    text = renderer(results)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Informe guardado en {args.output}")
    else:
        print(text, end="")

    if args.fail_on != "never":
        limit = SEVERITIES.index(args.fail_on)
        for _, findings in results:
            if any(SEVERITIES.index(f.severity) <= limit for f in findings):
                return 1
    return 0
