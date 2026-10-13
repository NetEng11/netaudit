"""Reglas de auditoría. Cada regla recibe una Config y devuelve una lista de hallazgos.

Para añadir una regla nueva basta con escribir una función y decorarla con @rule.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from .parser import Config

SEVERITIES = ("high", "medium", "low")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    device: str
    detail: str
    recommendation: str


Rule = Callable[[Config], "list[Finding]"]
RULES: "list[Rule]" = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


def _f(cfg: Config, rule_id: str, severity: str, title: str, detail: str, rec: str) -> Finding:
    return Finding(rule_id, severity, title, cfg.hostname, detail, rec)


@rule
def vty_ssh_only(cfg: Config) -> "list[Finding]":
    out = []
    for blk in cfg.blocks_starting("line vty"):
        transports = [c for c in blk.children if c.startswith("transport input")]
        if transports != ["transport input ssh"]:
            seen = transports[0] if transports else "sin 'transport input' (depende de la versión)"
            out.append(_f(
                cfg, "NA-001", "high", "Acceso remoto no restringido a SSH",
                f"{blk.header}: {seen}",
                "Configura 'transport input ssh' en todas las líneas VTY y desactiva Telnet.",
            ))
    return out


@rule
def enable_secret(cfg: Config) -> "list[Finding]":
    if cfg.has_global("enable secret"):
        return []
    if cfg.has_global("enable password"):
        detail = "Se usa 'enable password' (se guarda en claro o con cifrado débil)"
    else:
        detail = "No hay contraseña de modo privilegiado configurada"
    return [_f(
        cfg, "NA-002", "high", "Sin 'enable secret'", detail,
        "Define 'enable secret' con un hash fuerte y elimina 'enable password'.",
    )]


@rule
def snmp_communities(cfg: Config) -> "list[Finding]":
    out = []
    for blk in cfg.blocks_starting("snmp-server community"):
        parts = blk.header.split()
        name = parts[2] if len(parts) > 2 else ""
        access = parts[3].upper() if len(parts) > 3 else "RO"
        if name.lower() in {"public", "private"}:
            out.append(_f(
                cfg, "NA-003", "high", "Comunidad SNMP por defecto",
                f"Comunidad '{name}' con acceso {access}",
                "Cambia las comunidades por valores no triviales o migra a SNMPv3.",
            ))
        elif access == "RW":
            out.append(_f(
                cfg, "NA-003", "medium", "Comunidad SNMP de escritura",
                f"Comunidad con acceso {access}",
                "Evita el acceso RW por SNMP salvo necesidad real y restríngelo con una ACL.",
            ))
    return out


@rule
def ntp_configured(cfg: Config) -> "list[Finding]":
    if cfg.has_global("ntp server"):
        return []
    return [_f(
        cfg, "NA-004", "medium", "Sin servidor NTP",
        "No hay ningún 'ntp server' configurado",
        "Configura al menos dos servidores NTP para que los logs tengan hora fiable.",
    )]


@rule
def syslog_configured(cfg: Config) -> "list[Finding]":
    pattern = re.compile(r"^logging (host )?\d+\.\d+\.\d+\.\d+")
    if any(pattern.match(b.header) for b in cfg.blocks):
        return []
    return [_f(
        cfg, "NA-005", "medium", "Sin servidor de logs remoto",
        "No hay ningún destino 'logging host' configurado",
        "Envía los logs a un servidor syslog central para conservarlos y correlacionarlos.",
    )]


@rule
def ssh_version_2(cfg: Config) -> "list[Finding]":
    if cfg.has_global("ip ssh version 2"):
        return []
    return [_f(
        cfg, "NA-006", "medium", "SSH versión 2 no forzada",
        "Falta 'ip ssh version 2'",
        "Fuerza SSHv2 con 'ip ssh version 2'.",
    )]


@rule
def password_encryption(cfg: Config) -> "list[Finding]":
    if cfg.has_global("service password-encryption"):
        return []
    return [_f(
        cfg, "NA-007", "low", "Sin 'service password-encryption'",
        "Las contraseñas de tipo 7/0 pueden quedar legibles en la configuración",
        "Activa 'service password-encryption' y usa 'secret' siempre que sea posible.",
    )]


@rule
def login_banner(cfg: Config) -> "list[Finding]":
    if cfg.has_global("banner"):
        return []
    return [_f(
        cfg, "NA-008", "low", "Sin banner de acceso",
        "No hay ningún banner configurado",
        "Añade un banner legal de acceso autorizado.",
    )]


@rule
def trunks_allowed_vlans(cfg: Config) -> "list[Finding]":
    bad = [
        b.header.replace("interface ", "")
        for b in cfg.blocks_starting("interface ")
        if b.has_child("switchport mode trunk") and not b.has_child("switchport trunk allowed vlan")
    ]
    if not bad:
        return []
    return [_f(
        cfg, "NA-009", "medium", "Troncales sin lista de VLAN permitidas",
        "Interfaces: " + ", ".join(bad),
        "Limita cada troncal con 'switchport trunk allowed vlan' a las VLAN necesarias.",
    )]


@rule
def interface_descriptions(cfg: Config) -> "list[Finding]":
    bad = [
        b.header.replace("interface ", "")
        for b in cfg.blocks_starting("interface ")
        if not b.has_child("shutdown") and not b.has_child("description")
    ]
    if not bad:
        return []
    return [_f(
        cfg, "NA-010", "low", "Interfaces activas sin descripción",
        "Interfaces: " + ", ".join(bad),
        "Añade 'description' a cada interfaz activa para facilitar la operación.",
    )]


def audit(cfg: Config) -> "list[Finding]":
    findings: "list[Finding]" = []
    for r in RULES:
        findings.extend(r(cfg))
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(findings, key=lambda f: (order[f.severity], f.rule_id))
