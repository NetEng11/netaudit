# netaudit

Herramienta en Python para **auditar configuraciones de equipos de red** (sintaxis estilo Cisco IOS) y generar un informe con los fallos de seguridad y buenas prácticas, ordenados por severidad.

Funciona sobre ficheros de configuración exportados, así que **no necesita conectarse a ningún equipo** ni instalar dependencias: solo Python 3.9 o superior.

## Qué hace

- Lee uno o varios ficheros de configuración (`.cfg`, `.conf`, `.txt`).
- Aplica 10 reglas de seguridad y buenas prácticas.
- Genera el informe en texto, Markdown o JSON.
- Devuelve un código de salida distinto de 0 si encuentra hallazgos graves, para poder usarlo en una pipeline de CI.

## Uso rápido

```bash
# Informe en pantalla
python -m netaudit sample_configs

# Informe en Markdown guardado en un fichero
python -m netaudit sample_configs --format md --output informe.md

# Informe en JSON, sin fallar aunque haya hallazgos
python -m netaudit sample_configs --format json --fail-on never
```

Ejemplo de salida (con las configuraciones ficticias incluidas):

```
rtr-edge-01  (alta: 3, media: 3, baja: 3)
  [ALTA ] NA-001 Acceso remoto no restringido a SSH
          line vty 0 4: transport input all
  [ALTA ] NA-002 Sin 'enable secret'
          Se usa 'enable password' (se guarda en claro o con cifrado débil)
  ...
sw-core-01  (alta: 0, media: 0, baja: 0)
  Sin hallazgos.
```

Hay un informe completo de ejemplo en [`docs/example_report.md`](docs/example_report.md).

### Opciones

| Opción | Descripción |
|---|---|
| `path` | Fichero de configuración o carpeta con varios |
| `--format` | `text` (por defecto), `md` o `json` |
| `--output` | Guarda el informe en un fichero |
| `--fail-on` | `high` (por defecto), `medium`, `low` o `never`. Código de salida 1 si hay hallazgos de esa severidad o superior |

## Reglas incluidas

| ID | Severidad | Qué comprueba |
|---|---|---|
| NA-001 | Alta | Líneas VTY que permiten algo distinto de SSH (Telnet) |
| NA-002 | Alta | Falta `enable secret` o se usa `enable password` |
| NA-003 | Alta / Media | Comunidades SNMP por defecto (`public`/`private`) o con acceso RW |
| NA-004 | Media | Sin servidor NTP |
| NA-005 | Media | Sin servidor de logs remoto |
| NA-006 | Media | SSH versión 2 no forzada |
| NA-007 | Baja | Sin `service password-encryption` |
| NA-008 | Baja | Sin banner de acceso |
| NA-009 | Media | Troncales sin lista de VLAN permitidas |
| NA-010 | Baja | Interfaces activas sin descripción |

## Añadir una regla

Cada regla es una función que recibe la configuración y devuelve hallazgos. Se registra con el decorador `@rule` en `netaudit/rules.py`:

```python
@rule
def cdp_disabled_on_wan(cfg: Config) -> "list[Finding]":
    bad = [b.header for b in cfg.blocks_starting("interface ")
           if "WAN" in " ".join(b.children) and not b.has_child("no cdp enable")]
    if not bad:
        return []
    return [_f(cfg, "NA-011", "low", "CDP activo en interfaces WAN",
               ", ".join(bad), "Desactiva CDP con 'no cdp enable' en interfaces externas.")]
```

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## Limitaciones

- Analiza el **texto** de la configuración con reglas simples: no sustituye a una auditoría completa ni entiende todos los fabricantes ni todas las versiones de sistema operativo.
- Los banners de varias líneas no están soportados (usa banners de una sola línea).
- Las configuraciones de `sample_configs/` son **ficticias**, con direcciones IP reservadas para documentación (RFC 5737) y hashes de ejemplo sin valor real.
- Un resultado sin hallazgos no significa que el equipo sea seguro, solo que no incumple estas reglas.

## Ideas para ampliarlo

- Descargar las configuraciones de los equipos de forma automática (por ejemplo con Netmiko).
- Definir las reglas en un fichero YAML en lugar de en código.
- Informe en HTML y comparación entre dos auditorías para ver la evolución.
- Soporte para otras sintaxis (Junos, Huawei VRP).

## Licencia

MIT. Consulta el fichero `LICENSE`.
