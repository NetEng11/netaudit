"""Parser mínimo de configuraciones con sintaxis estilo Cisco IOS.

Convierte el texto de una configuración en una lista de bloques: cada línea sin
sangría abre un bloque y las líneas con sangría posteriores son sus hijos.
Un '!' cierra el bloque actual.

Limitación conocida: los banners de varias líneas no están soportados; usa
banners de una sola línea (banner motd ^Ctexto^C).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Block:
    header: str
    children: list[str] = field(default_factory=list)

    def has_child(self, prefix: str) -> bool:
        return any(child.startswith(prefix) for child in self.children)


@dataclass
class Config:
    hostname: str
    blocks: list[Block]
    source: str = ""

    def blocks_starting(self, prefix: str) -> list[Block]:
        return [b for b in self.blocks if b.header.startswith(prefix)]

    def has_global(self, prefix: str) -> bool:
        return any(b.header.startswith(prefix) for b in self.blocks)


def parse_config(text: str, source: str = "") -> Config:
    blocks: list[Block] = []
    current: Block | None = None
    hostname = source or "desconocido"

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.strip() == "!":
            current = None
            continue
        if line[0].isspace():
            if current is not None:
                current.children.append(line.strip())
            continue
        current = Block(header=line.strip())
        blocks.append(current)
        if current.header.startswith("hostname "):
            hostname = current.header.split(None, 1)[1]

    return Config(hostname=hostname, blocks=blocks, source=source)
