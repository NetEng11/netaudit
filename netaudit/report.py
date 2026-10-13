"""Generación de informes en texto, Markdown y JSON."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from datetime import date

from .rules import SEVERITIES, Finding

LABEL = {"high": "alta", "medium": "media", "low": "baja"}


def counts(findings: "list[Finding]") -> "dict[str, int]":
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in SEVERITIES}


def to_text(results) -> str:
    lines = []
    for cfg, findings in results:
        c = counts(findings)
        lines.append(f"{cfg.hostname}  (alta: {c['high']}, media: {c['medium']}, baja: {c['low']})")
        if not findings:
            lines.append("  Sin hallazgos.")
        for f in findings:
            lines.append(f"  [{LABEL[f.severity].upper():5}] {f.rule_id} {f.title}")
            lines.append(f"          {f.detail}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def to_json(results) -> str:
    data = {
        "devices": [
            {
                "device": cfg.hostname,
                "source": cfg.source,
                "counts": counts(findings),
                "findings": [asdict(f) for f in findings],
            }
            for cfg, findings in results
        ]
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def to_markdown(results) -> str:
    total = Counter()
    for _, findings in results:
        total.update(f.severity for f in findings)

    out = [
        "# Informe de auditoría de configuraciones",
        "",
        f"Fecha: {date.today().isoformat()}",
        "",
        f"Dispositivos analizados: **{len(results)}**. "
        f"Hallazgos: **{sum(total.values())}** "
        f"(alta: {total['high']}, media: {total['medium']}, baja: {total['low']}).",
        "",
        "## Resumen",
        "",
        "| Dispositivo | Alta | Media | Baja |",
        "|---|---:|---:|---:|",
    ]
    for cfg, findings in results:
        c = counts(findings)
        out.append(f"| {cfg.hostname} | {c['high']} | {c['medium']} | {c['low']} |")

    for cfg, findings in results:
        out += ["", f"## {cfg.hostname}", ""]
        if not findings:
            out.append("Sin hallazgos.")
            continue
        for sev in SEVERITIES:
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            out += [f"### Severidad {LABEL[sev]}", ""]
            for f in group:
                out.append(f"- **[{f.rule_id}] {f.title}**. {f.detail}.")
                out.append(f"  Recomendación: {f.recommendation}")
            out.append("")
    return "\n".join(out).rstrip() + "\n"
