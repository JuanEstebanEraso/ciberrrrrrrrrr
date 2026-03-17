"""
packet_sniffer.py  -  Capturador de tráfico real con Scapy

Captura paquetes TCP en el puerto 9999 directamente desde la interfaz de red,
tal como lo haría Wireshark. Muestra en pantalla los payloads crudos y confirma
que el contenido es ILEGIBLE (cifrado con AES-256-GCM).

Requisitos:
  - Windows: instalar Npcap con soporte de loopback
             https://npcap.com  →  marcar "Install Npcap in WinPcap API-compatible Mode"
             y "Support raw 802.11 traffic" + "Loopback Adapter"
  - Ejecutar esta terminal CON permisos de Administrador
  - pip install scapy

Uso:
  python packet_sniffer.py [--iface <interfaz>] [--port <puerto>]

  Si no sabes el nombre de tu interfaz, ejecuta:
    python packet_sniffer.py --list-ifaces
"""

import struct
import sys
import argparse
from datetime import datetime

# ── Verificar Scapy ───────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, TCP, IP, Raw, get_if_list, conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


_pkt_counter = 0

_TYPE_NAMES = {
    0x01: "CLAVE_PUBLICA_RSA",
    0x02: "CLAVE_SESION_CIFRADA_RSA",
    0x03: "MENSAJE_CIFRADO_AES256",
}


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b <= 126) / len(data)


def _show_packet(pkt, target_port: int) -> None:
    global _pkt_counter

    if TCP not in pkt or Raw not in pkt:
        return

    tcp     = pkt[TCP]
    payload = bytes(pkt[Raw])

    if tcp.sport != target_port and tcp.dport != target_port:
        return
    if len(payload) == 0:
        return

    _pkt_counter += 1
    ts        = datetime.now().strftime("%H:%M:%S.%f")
    src_ip    = pkt[IP].src if IP in pkt else "?"
    dst_ip    = pkt[IP].dst if IP in pkt else "?"
    direction = "A → B" if tcp.dport == target_port else "B → A"

    print(f"\n╔{'═'*63}╗")
    print(f"║  PKT #{_pkt_counter:<4}  {ts}  {direction:<29}║")
    print(f"╠{'═'*63}╣")
    print(f"║  {src_ip}:{tcp.sport}  →  {dst_ip}:{tcp.dport}"
          + " " * max(0, 40 - len(f"{src_ip}:{tcp.sport}  →  {dst_ip}:{tcp.dport}")) + "║")
    print(f"║  Tamaño payload: {len(payload)} bytes"
          + " " * max(0, 45 - len(str(len(payload)))) + "║")

    # Intentar parsear frame del protocolo
    if len(payload) >= 5:
        try:
            msg_type, length = struct.unpack(">BI", payload[:5])
            type_name = _TYPE_NAMES.get(msg_type, f"0x{msg_type:02x}")
            data_body = payload[5: 5 + length]

            ratio = _printable_ratio(data_body)

            print(f"╠{'═'*63}╣")
            print(f"║  Tipo protocolo: {type_name:<46}║")
            print(f"║  Longitud campo: {length} bytes"
                  + " " * max(0, 45 - len(str(length))) + "║")

            # HEX dump
            hex_s = data_body.hex()
            for i, chunk in enumerate([hex_s[j:j+48] for j in range(0, min(96, len(hex_s)), 48)]):
                lbl = "  HEX dump  :" if i == 0 else "             "
                print(f"║{lbl} {chunk:<50}║")

            # ASCII visual
            ascii_v = "".join(chr(b) if 32 <= b < 127 else "·" for b in data_body[:40])
            print(f"║  ASCII     : {ascii_v:<49}║")

            print(f"╠{'═'*63}╣")
            if msg_type == 0x03:
                if ratio < 0.30:
                    v = f"✓ CIFRADO  ({ratio:.0%} imprimible) — atacante NO puede leerlo"
                else:
                    v = f"⚠ POSIBLE TEXTO PLANO ({ratio:.0%} imprimible) — REVISAR"
                print(f"║  {v:<62}║")
            elif msg_type == 0x02:
                print(f"║  Clave AES encapsulada con RSA — solo el receptor puede abrirla║")
            elif msg_type == 0x01:
                print(f"║  Clave pública RSA (PEM) — no es secreta                      ║")
        except Exception:
            print(f"╠{'═'*63}╣")
            hex_raw = payload.hex()
            print(f"║  RAW HEX: {hex_raw[:53]}{'...' if len(hex_raw)>53 else ''}║")

    print(f"╚{'═'*63}╝")


def list_interfaces() -> None:
    """Muestra las interfaces disponibles para captura."""
    print("\nInterfaces de red disponibles:")
    for iface in get_if_list():
        print(f"  {iface}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Sniffer de tráfico cifrado con Scapy")
    parser.add_argument("--iface",       default=None,  help="Nombre de la interfaz (ej: lo, Ethernet)")
    parser.add_argument("--port",        type=int, default=9999, help="Puerto a capturar (default: 9999)")
    parser.add_argument("--list-ifaces", action="store_true",    help="Listar interfaces disponibles y salir")
    args = parser.parse_args()

    if not SCAPY_OK:
        print("ERROR: Scapy no está instalado.")
        print("  pip install scapy")
        print("  En Windows también necesitas Npcap: https://npcap.com")
        sys.exit(1)

    if args.list_ifaces:
        list_interfaces()
        sys.exit(0)

    print("╔" + "═" * 63 + "╗")
    print("║      SNIFFER DE TRÁFICO   ·   Captura con Scapy              ║")
    print("╠" + "═" * 63 + "╣")
    print(f"║  Puerto objetivo : {args.port:<44}║")
    iface_label = args.iface if args.iface else "auto (todas)"
    print(f"║  Interfaz        : {iface_label:<44}║")
    print("╠" + "═" * 63 + "╣")
    print("║  NOTA: En Windows requiere Npcap y permisos de Administrador  ║")
    print("║  Si falla, usa  proxy_sniffer.py  (no necesita permisos)     ║")
    print("╚" + "═" * 63 + "╝\n")
    print(f"Capturando paquetes en puerto {args.port} ...")
    print("Inicia node_server.py y node_client.py en otras terminales.")
    print("Presiona Ctrl+C para detener.\n")

    try:
        sniff(
            filter=f"tcp port {args.port}",
            prn=lambda p: _show_packet(p, args.port),
            store=False,
            iface=args.iface,
        )
    except PermissionError:
        print("\nERROR: Permisos insuficientes.")
        print("  Ejecuta esta terminal como Administrador.")
    except OSError as exc:
        print(f"\nERROR de interfaz: {exc}")
        print("  Usa  --list-ifaces  para ver las interfaces disponibles.")
        print("  Alternativamente usa proxy_sniffer.py (no necesita Npcap).")
    except KeyboardInterrupt:
        print(f"\n\nCaptura detenida. Total de paquetes capturados: {_pkt_counter}")


if __name__ == "__main__":
    main()
