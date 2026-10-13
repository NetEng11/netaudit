# Informe de auditoría de configuraciones

Fecha: 2026-10-13

Dispositivos analizados: **3**. Hallazgos: **14** (alta: 5, media: 5, baja: 4).

## Resumen

| Dispositivo | Alta | Media | Baja |
|---|---:|---:|---:|
| rtr-edge-01 | 3 | 3 | 3 |
| sw-access-02 | 2 | 2 | 1 |
| sw-core-01 | 0 | 0 | 0 |

## rtr-edge-01

### Severidad alta

- **[NA-001] Acceso remoto no restringido a SSH**. line vty 0 4: transport input all.
  Recomendación: Configura 'transport input ssh' en todas las líneas VTY y desactiva Telnet.
- **[NA-002] Sin 'enable secret'**. Se usa 'enable password' (se guarda en claro o con cifrado débil).
  Recomendación: Define 'enable secret' con un hash fuerte y elimina 'enable password'.
- **[NA-003] Comunidad SNMP por defecto**. Comunidad 'private' con acceso RW.
  Recomendación: Cambia las comunidades por valores no triviales o migra a SNMPv3.

### Severidad media

- **[NA-004] Sin servidor NTP**. No hay ningún 'ntp server' configurado.
  Recomendación: Configura al menos dos servidores NTP para que los logs tengan hora fiable.
- **[NA-005] Sin servidor de logs remoto**. No hay ningún destino 'logging host' configurado.
  Recomendación: Envía los logs a un servidor syslog central para conservarlos y correlacionarlos.
- **[NA-006] SSH versión 2 no forzada**. Falta 'ip ssh version 2'.
  Recomendación: Fuerza SSHv2 con 'ip ssh version 2'.

### Severidad baja

- **[NA-007] Sin 'service password-encryption'**. Las contraseñas de tipo 7/0 pueden quedar legibles en la configuración.
  Recomendación: Activa 'service password-encryption' y usa 'secret' siempre que sea posible.
- **[NA-008] Sin banner de acceso**. No hay ningún banner configurado.
  Recomendación: Añade un banner legal de acceso autorizado.
- **[NA-010] Interfaces activas sin descripción**. Interfaces: GigabitEthernet0/1.
  Recomendación: Añade 'description' a cada interfaz activa para facilitar la operación.


## sw-access-02

### Severidad alta

- **[NA-001] Acceso remoto no restringido a SSH**. line vty 0 15: transport input ssh telnet.
  Recomendación: Configura 'transport input ssh' en todas las líneas VTY y desactiva Telnet.
- **[NA-003] Comunidad SNMP por defecto**. Comunidad 'public' con acceso RO.
  Recomendación: Cambia las comunidades por valores no triviales o migra a SNMPv3.

### Severidad media

- **[NA-005] Sin servidor de logs remoto**. No hay ningún destino 'logging host' configurado.
  Recomendación: Envía los logs a un servidor syslog central para conservarlos y correlacionarlos.
- **[NA-009] Troncales sin lista de VLAN permitidas**. Interfaces: GigabitEthernet0/1.
  Recomendación: Limita cada troncal con 'switchport trunk allowed vlan' a las VLAN necesarias.

### Severidad baja

- **[NA-010] Interfaces activas sin descripción**. Interfaces: GigabitEthernet0/2, GigabitEthernet0/3.
  Recomendación: Añade 'description' a cada interfaz activa para facilitar la operación.


## sw-core-01

Sin hallazgos.
