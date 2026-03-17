"""
node_client.py  -  Nodo A  (Cliente)

Protocolo de handshake:
  1. Genera par de claves RSA 2048-bit
  2. Recibe la clave pública RSA de Node B  ←  [MSG_TYPE_PUBLIC_KEY]
  3. Envía su clave pública RSA a Node B    →  [MSG_TYPE_PUBLIC_KEY]
  4. Genera clave de sesión AES-256 aleatoria
  5. Cifra la clave de sesión con la clave pública RSA de Node B
  6. Envía la clave de sesión cifrada       →  [MSG_TYPE_SESSION_KEY]
     (solo Node B puede descifrarla con su clave privada)
  7. Canal seguro establecido → todos los mensajes  [MSG_TYPE_MESSAGE]
     son cifrados con AES-256-GCM

Uso normal:
  python node_client.py

Uso con proxy sniffer (para captura de tráfico):
  python node_client.py --port 9998
"""

import socket
import threading
import sys
import argparse

from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    rsa_encrypt,
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    send_frame,
    recv_frame,
    MSG_TYPE_PUBLIC_KEY,
    MSG_TYPE_SESSION_KEY,
    MSG_TYPE_MESSAGE,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
NODE_NAME    = "Node A (Cliente)"
SEP          = "─" * 60


def banner(msg: str) -> None:
    print(f"\n{'═'*60}")
    print(f"  {msg}")
    print(f"{'═'*60}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Node A - Cliente cifrado")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"IP del servidor (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Puerto destino (default: {DEFAULT_PORT})")
    args = parser.parse_args()

    banner(f"{NODE_NAME}  ·  Conectando a {args.host}:{args.port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((args.host, args.port))
    except ConnectionRefusedError:
        print(f"[{NODE_NAME}] ERROR: No se pudo conectar a {args.host}:{args.port}")
        print(f"  Asegúrate de que node_server.py esté corriendo primero.")
        sys.exit(1)

    print(f"[{NODE_NAME}] Conectado a {args.host}:{args.port}")

    # ── 1. Generar par de claves RSA ──────────────────────────────────────────
    print(f"[{NODE_NAME}] Generando par de claves RSA 2048-bit...")
    private_key, public_key = generate_rsa_keypair()
    pub_pem = serialize_public_key(public_key)
    print(f"[{NODE_NAME}] Clave pública RSA generada:")
    print(f"  {pub_pem.decode()[:60].strip()}...")

    # ── 2. Recibir clave pública de Node B ────────────────────────────────────
    msg_type, server_pub_bytes = recv_frame(sock)
    if msg_type != MSG_TYPE_PUBLIC_KEY:
        print(f"[{NODE_NAME}] ERROR: Se esperaba clave pública, se recibió tipo 0x{msg_type:02x}")
        sock.close()
        sys.exit(1)
    server_public_key = deserialize_public_key(server_pub_bytes)
    print(f"[{NODE_NAME}] ◄ Clave pública RSA de Node B recibida")

    # ── 3. Enviar nuestra clave pública ───────────────────────────────────────
    send_frame(sock, MSG_TYPE_PUBLIC_KEY, pub_pem)
    print(f"[{NODE_NAME}] ► Clave pública RSA enviada a Node B")

    # ── 4. Generar clave de sesión AES-256 ────────────────────────────────────
    session_key = generate_aes_key()
    print(f"[{NODE_NAME}] Clave de sesión AES-256 generada:")
    print(f"  Clave AES (hex): {session_key.hex()}")

    # ── 5-6. Cifrar y enviar clave de sesión con RSA de Node B ────────────────
    enc_session_key = rsa_encrypt(server_public_key, session_key)
    print(f"[{NODE_NAME}] Clave de sesión cifrada con RSA público de Node B:")
    print(f"  HEX cifrado: {enc_session_key.hex()[:72]}...")
    send_frame(sock, MSG_TYPE_SESSION_KEY, enc_session_key)
    print(f"[{NODE_NAME}] ► Clave de sesión enviada (cifrada con RSA — solo Node B puede descifrarla)")

    banner(f"{NODE_NAME}  ·  CANAL SEGURO ESTABLECIDO")
    print("  Algoritmo de sesión : AES-256-GCM (cifrado autenticado)")
    print("  Intercambio de clave: RSA-OAEP-SHA256")
    print("  Todos los mensajes están cifrados de extremo a extremo.")
    print(f"\nEscribe mensajes para enviar a Node B (o 'salir' para terminar):\n")

    # ── Hilo receptor ─────────────────────────────────────────────────────────
    def receive_loop() -> None:
        while True:
            try:
                msg_type, data = recv_frame(sock)
                if msg_type is None:
                    print(f"\n[{NODE_NAME}] Conexión cerrada por Node B.")
                    break
                if msg_type == MSG_TYPE_MESSAGE:
                    plaintext = aes_decrypt(session_key, data)
                    print(f"\n{SEP}")
                    print(f"  Node B  -->  Node A")
                    print(f"  Datos cifrados en red (hex): {data.hex()[:72]}...")
                    print(f"  Mensaje descifrado         : \"{plaintext}\"")
                    print(f"{SEP}")
                    print(f"[{NODE_NAME}] Escribe un mensaje: ", end="", flush=True)
            except Exception as exc:
                print(f"\n[{NODE_NAME}] Conexión cerrada: {exc}")
                break

    recv_thread = threading.Thread(target=receive_loop, daemon=True)
    recv_thread.start()

    # ── Bucle de envío ────────────────────────────────────────────────────────
    while True:
        try:
            msg = input(f"[{NODE_NAME}] Escribe un mensaje: ")
        except (EOFError, KeyboardInterrupt):
            break

        if msg.lower() == "salir":
            break

        encrypted = aes_encrypt(session_key, msg)
        print(f"  ► Enviando cifrado (hex): {encrypted.hex()[:72]}...")
        try:
            send_frame(sock, MSG_TYPE_MESSAGE, encrypted)
        except Exception as exc:
            print(f"[{NODE_NAME}] Error al enviar: {exc}")
            break

    sock.close()
    print(f"\n[{NODE_NAME}] Sesión finalizada.")


if __name__ == "__main__":
    main()
