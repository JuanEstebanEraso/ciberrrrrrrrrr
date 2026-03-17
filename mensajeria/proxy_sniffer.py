"""
proxy_sniffer.py  -  Proxy TCP transparente  /  Capturador de tráfico cifrado

Simula lo que vería un atacante que intercepta la comunicación en la red.
Actúa como un Man-in-the-Middle (MITM) a nivel de transporte TCP:
  - Se pone entre Node A y Node B
  - Reenvía todos los bytes sin modificarlos
  - Muestra en pantalla CADA paquete tal como viaja por la red
  - Prueba que el contenido es ILEGIBLE (cifrado con AES-256-GCM)

Topología con proxy activo:
  Node A (puerto 9998 → proxy) ↔  PROXY  ↔  Node B (puerto 9999)

Instrucciones de uso:
  Terminal 1:  python node_server.py          (escucha en puerto 9999)
  Terminal 2:  python proxy_sniffer.py        (escucha en puerto 9998)
  Terminal 3:  python node_client.py --port 9998  (conecta al proxy)

El proxy intercepta y muestra TODO el tráfico crudo → demuestra cifrado.
"""

import socket
import struct
import threading
from datetime import datetime

PROXY_HOST  = "127.0.0.1"
PROXY_PORT  = 9998      # Node A se conecta aquí
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 9999      # Node B está aquí

_lock        = threading.Lock()
_pkt_counter = 0


# ── Análisis de frames del protocolo ─────────────────────────────────────────

_TYPE_NAMES = {
    0x01: "INTERCAMBIO_CLAVE_PUBLICA_RSA",
    0x02: "CLAVE_SESION_CIFRADA_RSA",
    0x03: "MENSAJE_CIFRADO_AES256",
}


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b <= 126) / len(data)


def _analyze_and_display(raw: bytes, direction: str) -> None:
    """Parsea uno o más frames del protocolo y los imprime en pantalla."""
    global _pkt_counter
    offset = 0

    while offset < len(raw):
        # Necesitamos al menos el header de 5 bytes
        if offset + 5 > len(raw):
            with _lock:
                print(f"\n  [fragmento incompleto {len(raw)-offset} bytes, no se puede parsear]")
            break

        msg_type, length = struct.unpack(">BI", raw[offset: offset + 5])
        payload_start = offset + 5
        payload_end   = payload_start + length

        if payload_end > len(raw):
            # Frame parcial en este segmento TCP — sólo mostramos el header
            payload = raw[payload_start:]
        else:
            payload = raw[payload_start:payload_end]

        type_name = _TYPE_NAMES.get(msg_type, f"TIPO_DESCONOCIDO(0x{msg_type:02x})")
        ratio     = _printable_ratio(payload)
        ts        = datetime.now().strftime("%H:%M:%S.%f")

        with _lock:
            _pkt_counter += 1
            n = _pkt_counter

            print(f"\n╔{'═'*63}╗")
            print(f"║  PAQUETE #{n:<4}  {ts}  {direction:<25}║")
            print(f"╠{'═'*63}╣")
            print(f"║  Tipo     : {type_name:<51}║")
            print(f"║  Tamaño   : {length} bytes{' '*(50-len(str(length)))}║")

            # HEX dump (primeras 3 líneas de 24 bytes)
            hex_full = payload.hex()
            for i, chunk in enumerate([hex_full[j:j+48] for j in range(0, min(144, len(hex_full)), 48)]):
                label = "  HEX      :" if i == 0 else "             "
                print(f"║{label} {chunk:<51}║")

            # ASCII visual (puntos para no-imprimibles)
            ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:36])
            print(f"║  ASCII    : {ascii_repr:<51}║")
            print(f"╠{'═'*63}╣")

            # Veredicto de cifrado
            if msg_type == 0x03:
                if ratio < 0.30:
                    verdict = f"✓ CIFRADO  — ratio imprimible: {ratio:.0%} — ilegible para atacante"
                else:
                    verdict = f"⚠ POSIBLE TEXTO PLANO — ratio: {ratio:.0%} — REVISAR"
                print(f"║  {verdict:<62}║")
            elif msg_type == 0x02:
                print(f"║  Clave AES cifrada con RSA — sin clave privada es ilegible   ║")
            elif msg_type == 0x01:
                print(f"║  Clave pública RSA (información pública, no secreta)          ║")

            print(f"╚{'═'*63}╝")

        offset = payload_end


# ── Forwarding TCP ────────────────────────────────────────────────────────────

def _forward(src: socket.socket, dst: socket.socket, direction: str) -> None:
    """Lee de src, imprime y reenvía a dst."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            _analyze_and_display(data, direction)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def _handle_connection(client_sock: socket.socket, client_addr) -> None:
    print(f"\n[Proxy] ▶ Conexión entrante desde {client_addr[0]}:{client_addr[1]}")
    print(f"[Proxy]   Conectando con Node B en {TARGET_HOST}:{TARGET_PORT} ...")

    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((TARGET_HOST, TARGET_PORT))
    except ConnectionRefusedError:
        print(f"[Proxy] ERROR: Node B no está disponible en {TARGET_HOST}:{TARGET_PORT}")
        print(f"         Inicia primero node_server.py")
        client_sock.close()
        return

    print(f"[Proxy]   Puente establecido. Capturando tráfico...\n")

    t_a_to_b = threading.Thread(
        target=_forward,
        args=(client_sock, server_sock, "Node A ──► Node B"),
        daemon=True,
    )
    t_b_to_a = threading.Thread(
        target=_forward,
        args=(server_sock, client_sock, "Node B ──► Node A"),
        daemon=True,
    )
    t_a_to_b.start()
    t_b_to_a.start()
    t_a_to_b.join()
    t_b_to_a.join()
    print(f"\n[Proxy] Sesión {client_addr[0]}:{client_addr[1]} finalizada.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("╔" + "═" * 63 + "╗")
    print("║       PROXY SNIFFER  ·  Capturador de Tráfico Cifrado        ║")
    print("╠" + "═" * 63 + "╣")
    print(f"║  Escucha (Node A)  : {PROXY_HOST}:{PROXY_PORT:<42}║")
    print(f"║  Reenvía (Node B)  : {TARGET_HOST}:{TARGET_PORT:<42}║")
    print("╠" + "═" * 63 + "╣")
    print("║  INSTRUCCIONES:                                               ║")
    print("║  1. python node_server.py                                     ║")
    print("║  2. python proxy_sniffer.py   (esta ventana)                 ║")
    print(f"║  3. python node_client.py --port {PROXY_PORT:<30}║")
    print("║                                                               ║")
    print("║  El proxy ve TODOS los bytes pero NO puede descifrarlos.      ║")
    print("╚" + "═" * 63 + "╝\n")

    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_sock.bind((PROXY_HOST, PROXY_PORT))
    proxy_sock.listen(5)
    print(f"[Proxy] Escuchando en {PROXY_HOST}:{PROXY_PORT} ...")
    print(f"[Proxy] Presiona Ctrl+C para detener.\n")

    try:
        while True:
            client_sock, client_addr = proxy_sock.accept()
            t = threading.Thread(
                target=_handle_connection,
                args=(client_sock, client_addr),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[Proxy] Detenido por el usuario.")
    finally:
        proxy_sock.close()


if __name__ == "__main__":
    main()
