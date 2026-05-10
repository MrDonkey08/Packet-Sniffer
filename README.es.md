# Packet Sniffer

[![en](https://img.shields.io/badge/lang-en-red.svg)](./README.md)
[![es](https://img.shields.io/badge/lang-es-blue.svg)](./README.es.md)

## Tabla de Contenidos

<!--toc:start-->

- [Packet Sniffer](#packet-sniffer)
  - [Tabla de Contenidos](#tabla-de-contenidos)
  - [Acerca](#acerca)
  - [Instalación](#instalación)
    - [Requisitos Previos](#requisitos-previos)
    - [Clonar el Repositorio](#clonar-el-repositorio)
    - [Instalar Dependencias](#instalar-dependencias)
  - [Uso](#uso)
    - [Modo Archivo](#modo-archivo)
    - [Modo Captura en Vivo](#modo-captura-en-vivo)
    - [Referencia de Opciones](#referencia-de-opciones)
  - [Supuestos](#supuestos)
  - [Notas Importantes](#notas-importantes)
  <!--toc:end-->

## Acerca

Sniffer de paquetes de red escrito en Python que permite capturar y diseccionar
tráfico en vivo desde una interfaz de red, o analizar un archivo binario de
paquetes capturados previamente.

El analizador descompone los paquetes capa por capa siguiendo el modelo OSI:

| Capa                 | Protocolos soportados                         |
| -------------------- | --------------------------------------------- |
| Enlace de datos (L2) | Ethernet II, 802.1Q VLAN, ARP                 |
| Red (L3)             | IPv4, IPv6                                    |
| Transporte (L4)      | TCP, UDP, ICMPv4, ICMPv6                      |
| Aplicación (L7)      | DNS, DHCPv4, DHCPv6, HTTP/1.x, ONC RPC, NFSv4 |

## Instalación

### Requisitos Previos

- Python 3.10 o superior (se usan anotaciones de tipo `X | Y`)
- Privilegios de superusuario para captura en vivo (`CAP_NET_RAW`)
- [`uv`](https://docs.astral.sh/uv/) como gestor de entornos y dependencias

### Clonar el Repositorio

```bash
git clone https://github.com/MrDonkey08/packet-sniffer.git
cd packet-sniffer
```

> [!TIP]
>
> Puedes agregar la opción `--depth=1` para clonar solamente el commit más
> reciente.

### Instalar Dependencias

```bash
uv sync
```

Las dependencias del proyecto están declaradas en `pyproject.toml`. Las
principales son:

- [`scapy`](https://scapy.net/) — captura asíncrona de paquetes en vivo
- [`typer`](https://typer.tiangolo.com/) — interfaz de línea de comandos

## Uso

El punto de entrada es `src/main.py` y puede ser ejecutado ya sea con `uv run`,
`python3` o directamente (e.g., `src/main.py` ).

Hay dos modos de operación:

- [Modo Archivo](#modo-archivo)
- [Modo Captura en Vivo](#modo-captura-en-vivo)

### Modo Archivo

Analiza un archivo binario que contenga un único frame Ethernet en crudo:

```bash
uv run src/main.py <archivo>
```

```bash
# e.g., analizar un frame capturado previamente
uv run src/main.py captures/dns_query.bin
```

### Modo Captura en Vivo

Captura paquetes en tiempo real sobre una interfaz de red:

```bash
sudo uv run src/main.py --iface <interfaz>
```

Se puede combinar con un filtro BPF mediante `--filter` / `-f`:

```bash
# e.g., capturar solo tráfico DNS en eth0
sudo uv run src/main.py --iface eth0 --filter "udp port 53"

# e.g., capturar tráfico TCP en el puerto 80 o 443
sudo uv run src/main.py -i eth0 -f "tcp port 80 or tcp port 443"
```

Presionar `Ctrl+C` detiene la captura de forma limpia.

### Referencia de Opciones

```console
$ uv run src/main.py --help

 Usage: main.py [OPTIONS] [FILE]

╭─ Arguments ──────────────────────────────────────────────────────────────────────────╮
│   file      [FILE]  Raw packet binary file (omit for live capture)                   │
╰──────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────╮
│ --iface               -i      TEXT  Network interface for live capture (e.g., eth0)  │
│ --filter              -f      TEXT  BPF filter string (e.g., 'tcp port 80')          │
│ --install-completion                Install completion for the current shell.        │
│ --show-completion                   Show completion for the current shell, to copy   │
│                                     it or customize the installation.                │
│ --help                              Show this message and exit.                      │
╰──────────────────────────────────────────────────────────────────────────────────────
```

## Supuestos

- Los archivos binarios de entrada contienen exactamente un frame Ethernet II
  completo, incluyendo el FCS de 4 bytes al final (aunque Wireshark suele
  omitirlo en las capturas).

- En capturas en vivo, Scapy proporciona los frames sin FCS; el parser lo maneja
  correctamente al calcular los offsets del payload.

- El campo EtherType se usa para determinar el protocolo de red. Tramas con
  EtherTypes no reconocidos (i.e., distintos de `0x0800`, `0x86DD`, `0x0806`) se
  reportan pero no se analizan en profundidad.

- La detección de protocolos de aplicación se basa exclusivamente en el número
  de puerto (e.g., puerto 53 → DNS, puerto 80/443 → HTTP). No se realiza
  inspección profunda de payload para inferir el protocolo.

- Para NFS, se asume que los mensajes TCP llevan un prefijo de 4 bytes de
  longitud del registro (record marking, RFC 5531 §11) que se descarta antes de
  parsear el RPC.

- Los frames 802.1Q con doble etiquetado (QinQ, EtherType `0x88A8`) no están
  soportados.

## Notas Importantes

- **Privilegios**: la captura en vivo requiere ejecutar el script como root o
  con la capability `CAP_NET_RAW`. En Linux esto puede concederse con:

  ```bash
  sudo setcap cap_net_raw+eip $(which python3)
  ```

- **Fragmentación IP**: los fragmentos IP distintos del primero (fragment offset
  ≠ 0) carecen de cabecera de transporte. El parser intentará parsear el payload
  como protocolo de transporte y fallará silenciosamente; no se realiza
  reensamblado.

- **HTTP cifrado**: el parser de HTTP/1.x opera sobre texto plano. El tráfico
  HTTPS (`puerto 443`) aparecerá como datos binarios no interpretables en el
  campo body.

- **Errores de parseo**: los paquetes malformados o truncados generan
  advertencias en _stdout_, pero no detienen la ejecución. Las capas que no
  puedan parsearse muestran los bytes en hexadecimal como fallback.

- **IPv6 Extension Headers**: los extension headers de IPv6 (e.g., Hop-by-Hop,
  Routing, Fragment) no se parsean; el campo `next_header` se reporta con su
  valor numérico y el payload se trata directamente como el protocolo de
  transporte indicado.
