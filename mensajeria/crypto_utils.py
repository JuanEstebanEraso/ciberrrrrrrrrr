"""
crypto_utils.py - Utilidades criptográficas para comunicación segura

Implementa:
  - RSA 2048-bit:  generación de claves, cifrado/descifrado, serialización
  - AES-256-GCM:   cifrado autenticado de mensajes
  - Protocolo de framing TCP:  [tipo:1B][longitud:4B][payload:NB]

Tipos de mensaje del protocolo:
  0x01  CLAVE_PUBLICA   - Intercambio de clave pública RSA (PEM)
  0x02  CLAVE_SESION    - Clave AES cifrada con RSA (handshake)
  0x03  MENSAJE         - Mensaje cifrado con AES-256-GCM
"""

import os
import struct

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Constantes del protocolo ─────────────────────────────────────────────────
MSG_TYPE_PUBLIC_KEY  = 0x01
MSG_TYPE_SESSION_KEY = 0x02
MSG_TYPE_MESSAGE     = 0x03


# ── RSA ───────────────────────────────────────────────────────────────────────

def generate_rsa_keypair():
    """Genera un par de claves RSA de 2048 bits."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> bytes:
    """Serializa la clave pública RSA en formato PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_data: bytes):
    """Deserializa una clave pública RSA desde PEM."""
    return serialization.load_pem_public_key(pem_data)


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Cifra datos con la clave pública RSA usando relleno OAEP-SHA256."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Descifra datos con la clave privada RSA usando relleno OAEP-SHA256."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """Genera una clave AES aleatoria de 256 bits (32 bytes)."""
    return os.urandom(32)


def aes_encrypt(key: bytes, plaintext: str) -> bytes:
    """
    Cifra un mensaje de texto con AES-256-GCM.
    Devuelve:  nonce (12 B) || ciphertext+tag
    El nonce es aleatorio en cada llamada, garantizando que el mismo mensaje
    produce siempre un cifrado distinto.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext


def aes_decrypt(key: bytes, data: bytes) -> str:
    """
    Descifra un mensaje AES-256-GCM.
    Espera:  nonce (12 B) || ciphertext+tag
    Lanza InvalidTag si los datos fueron alterados (autenticación fallida).
    """
    aesgcm = AESGCM(key)
    nonce      = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


# ── Protocolo de framing TCP ──────────────────────────────────────────────────

def send_frame(sock, msg_type: int, payload: bytes) -> None:
    """
    Envía un frame: [tipo:1B][longitud:4B][payload:NB]
    Usa sendall para garantizar el envío completo.
    """
    header = struct.pack(">BI", msg_type, len(payload))
    sock.sendall(header + payload)


def recv_frame(sock):
    """
    Recibe un frame completo del socket.
    Devuelve (msg_type, payload) o (None, None) si la conexión se cerró.
    """
    try:
        header = _recv_exactly(sock, 5)
    except ConnectionError:
        return None, None
    msg_type, length = struct.unpack(">BI", header)
    payload = _recv_exactly(sock, length)
    return msg_type, payload


def _recv_exactly(sock, n: int) -> bytes:
    """Lee exactamente n bytes del socket, bloqueando hasta conseguirlos."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexión cerrada inesperadamente.")
        buf += chunk
    return buf
