"""
node_server.py  -  Nodo B  (Servidor)

Protocolo de handshake:
  1. Genera par de claves RSA 2048-bit
  2. Envía su clave pública a Node A  →  [MSG_TYPE_PUBLIC_KEY]
  3. Recibe la clave pública de Node A ←  [MSG_TYPE_PUBLIC_KEY]
  4. Recibe la clave de sesión AES-256 cifrada con su clave pública RSA
     ←  [MSG_TYPE_SESSION_KEY]  (solo Node B puede descifrarla)
  5. Canal seguro establecido  → todos los mensajes  [MSG_TYPE_MESSAGE]
     son cifrados con AES-256-GCM

Uso:
  python node_server.py
"""

import socket
import threading
import sys

from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    rsa_decrypt,
    aes_encrypt,
    aes_decrypt,
    send_frame,
    recv_frame,
    MSG_TYPE_PUBLIC_KEY,
    MSG_TYPE_SESSION_KEY,
    MSG_TYPE_MESSAGE,
)

HOST      = "127.0.0.1"
PORT      = 9999
NODE_NAME = "Node B (Servidor)"
SEP       = "─" * 60


def banner(msg: str) -> None:
    print(f"\n{'═'*60}")
    print(f"  {msg}")
    print(f"{'═'*60}")


def handle_client(conn: socket.socket, addr) -> None:
    print(f"\n[{NODE_NAME}] Conexión recibida desde {addr[0]}:{addr[1]}")

    # ── 1. Generar par de claves RSA ──────────────────────────────────────────
    print(f"[{NODE_NAME}] Generando par de claves RSA 2048-bit...")
    private_key, public_key = generate_rsa_keypair()
    pub_pem = serialize_public_key(public_key)
    print(f"[{NODE_NAME}] Clave pública RSA generada:")
    print(f"  {pub_pem.decode()[:60].strip()}...")

    # ── 2. Enviar clave pública al cliente ────────────────────────────────────
    send_frame(conn, MSG_TYPE_PUBLIC_KEY, pub_pem)
    print(f"[{NODE_NAME}] ► Clave pública RSA enviada a Node A")

    # ── 3. Recibir clave pública de Node A ────────────────────────────────────
    msg_type, peer_pub_bytes = recv_frame(conn)
    if msg_type != MSG_TYPE_PUBLIC_KEY:
        print(f"[{NODE_NAME}] ERROR: Se esperaba clave pública, se recibió tipo 0x{msg_type:02x}")
        conn.close()
        return
    peer_public_key = deserialize_public_key(peer_pub_bytes)
    print(f"[{NODE_NAME}] ◄ Clave pública RSA de Node A recibida")

    # ── 4. Recibir clave de sesión AES cifrada ────────────────────────────────
    msg_type, enc_session_key = recv_frame(conn)
    if msg_type != MSG_TYPE_SESSION_KEY:
        print(f"[{NODE_NAME}] ERROR: Se esperaba clave de sesión, se recibió tipo 0x{msg_type:02x}")
        conn.close()
        return

    print(f"[{NODE_NAME}] ◄ Clave de sesión cifrada recibida ({len(enc_session_key)} bytes):")
    print(f"  HEX cifrado: {enc_session_key.hex()[:72]}...")

    session_key = rsa_decrypt(private_key, enc_session_key)
    print(f"[{NODE_NAME}] Clave de sesión AES-256 descifrada con clave privada RSA:")
    print(f"  Clave AES (hex): {session_key.hex()}")

    banner(f"{NODE_NAME}  ·  CANAL SEGURO ESTABLECIDO")
    print("  Algoritmo de sesión : AES-256-GCM (cifrado autenticado)")
    print("  Intercambio de clave: RSA-OAEP-SHA256")
    print("  Todos los mensajes están cifrados de extremo a extremo.")
    print(f"\nEscribe mensajes para enviar a Node A (o 'salir' para terminar):\n")

    # ── Hilo receptor ─────────────────────────────────────────────────────────
    def receive_loop() -> None:
        while True:
            try:
                msg_type, data = recv_frame(conn)
                if msg_type is None:
                    print(f"\n[{NODE_NAME}] Conexión cerrada por Node A.")
                    break
                if msg_type == MSG_TYPE_MESSAGE:
                    plaintext = aes_decrypt(session_key, data)
                    print(f"\n{SEP}")
                    print(f"  Node A  -->  Node B")
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
            send_frame(conn, MSG_TYPE_MESSAGE, encrypted)
        except Exception as exc:
            print(f"[{NODE_NAME}] Error al enviar: {exc}")
            break

    conn.close()
    print(f"\n[{NODE_NAME}] Sesión finalizada.")


def main() -> None:
    banner(f"{NODE_NAME}  ·  Puerto {PORT}")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    print(f"[{NODE_NAME}] Escuchando en {HOST}:{PORT} ...")
    print(f"[{NODE_NAME}] Esperando conexión de Node A...")

    try:
        conn, addr = server_sock.accept()
        handle_client(conn, addr)
    except KeyboardInterrupt:
        print(f"\n[{NODE_NAME}] Interrumpido.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
