import os
import stat
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from utils import load_env

load_env()
password = os.environ.get("MESH_PASSWORD", "").encode()


KEY_DIR = "./keys"
PRIVATE_FILE = os.path.join(KEY_DIR, "private.key")
PUBLIC_FILE  = os.path.join(KEY_DIR, "public.key")

ED25519_KEY_SIZE   = 32
HMAC_DERIVE_LENGTH = 32

# ----------------------------
# Sichere Dateierstellung mit korrekten Permissions von Anfang an
# FIX: Permissions werden VOR dem Schreiben gesetzt (kein TOCTOU-Fenster)
# ----------------------------
def _open_secure(path: str):
    """Öffnet/erstellt eine Datei mit 0o600 – atomisch, kein Race-Window."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, "wb")

def _check_permissions(path: str) -> None:
    """Warnt, wenn die Datei für andere lesbar ist."""
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(
            f"{path} ist zu offen ({oct(mode)}). Erwartet: 0o600."
        )

# ----------------------------
# Key laden oder erzeugen
# ----------------------------
def load_or_create_keys(password: bytes) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    os.makedirs(KEY_DIR, exist_ok=True)
    os.chmod(KEY_DIR, 0o700)

    if os.path.exists(PRIVATE_FILE) and os.path.exists(PUBLIC_FILE):
        return load_keys(password)  
    return create_keys(password)    

# ----------------------------
# Neue Keys erzeugen
# FIX: Private Key wird mit AES-256-GCM verschlüsselt gespeichert.
#      Das Passwort kommt hier als Parameter – nie hardcoden!
# ----------------------------
def create_keys(password: bytes) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()

    raw_priv = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),  # Verschlüsselung machen wir selbst
    )
    raw_pub = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # FIX: Private Key mit AES-256-GCM + zufälligem Salt & Nonce verschlüsseln
    encrypted_priv = _encrypt_key(raw_priv, password)

    with _open_secure(PRIVATE_FILE) as f:
        f.write(encrypted_priv)
    with _open_secure(PUBLIC_FILE) as f:
        f.write(raw_pub)

    return private_key, public_key

# ----------------------------
# Keys laden
# FIX: Längenvalidierung der gelesenen Bytes
# ----------------------------
def load_keys(password: bytes) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    _check_permissions(PRIVATE_FILE)
    _check_permissions(PUBLIC_FILE)

    with open(PRIVATE_FILE, "rb") as f:
        encrypted_priv = f.read()
    with open(PUBLIC_FILE, "rb") as f:
        pub_bytes = f.read()

    # FIX: Größen prüfen bevor wir Bytes an Krypto-Funktionen übergeben
    if len(pub_bytes) != ED25519_KEY_SIZE:
        raise ValueError(f"Public Key hat ungültige Länge: {len(pub_bytes)}")

    raw_priv = _decrypt_key(encrypted_priv, password)
    if len(raw_priv) != ED25519_KEY_SIZE:
        raise ValueError(f"Private Key hat ungültige Länge nach Entschlüsselung: {len(raw_priv)}")

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)
    pub  = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    return priv, pub


def load_public_key() -> tuple[bytes, ed25519.Ed25519PublicKey]:
    """Lädt nur den Public Key – kein Passwort nötig."""
    _check_permissions(PUBLIC_FILE)
    with open(PUBLIC_FILE, "rb") as f:
        pub_bytes = f.read()
    if len(pub_bytes) != ED25519_KEY_SIZE:
        raise ValueError(f"Public Key hat ungültige Länge: {len(pub_bytes)}")
    return pub_bytes, ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

# ----------------------------
# AES-256-GCM Hilfsfunktionen für Key-Verschlüsselung
# Format: salt(16) || nonce(12) || ciphertext+tag
# ----------------------------
def _derive_aes_key(password: bytes, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256: langsame KDF schützt gegen Brute-Force."""
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations=600_000, dklen=32)

def _encrypt_key(raw_key: bytes, password: bytes) -> bytes:
    salt  = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    aes_key = _derive_aes_key(password, salt)
    ct = AESGCM(aes_key).encrypt(nonce, raw_key, None)
    return salt + nonce + ct

def _decrypt_key(blob: bytes, password: bytes) -> bytes:
    if len(blob) < 16 + 12 + ED25519_KEY_SIZE + 16:  # salt+nonce+key+GCM-tag
        raise ValueError("Verschlüsselter Key-Blob ist zu kurz.")
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    aes_key = _derive_aes_key(password, salt)
    return AESGCM(aes_key).decrypt(nonce, ct, None)  # wirft InvalidTag bei Manipulation

# ----------------------------
# Adressableitung
# FIX 1: secrets statt random (random war kryptografisch unsicher)
# FIX 2: Längentrennzeichen verhindert Kollisionen (index="A", nonce="BC" ≠ index="AB", nonce="C")
# FIX 3: Kein Hostname mehr als Schlüssel (war vorhersehbar & niedrige Entropie)
# ----------------------------
def base_address(pub_bytes: bytes) -> str:
    if len(pub_bytes) != ED25519_KEY_SIZE:
        raise ValueError("Ungültige Public-Key-Länge.")
    return hashlib.sha256(pub_bytes).hexdigest()[:HMAC_DERIVE_LENGTH]

def derive_address(master_secret: bytes, index: bytes, nonce: bytes) -> str:
    """
    Leitet eine Adresse sicher per HMAC-SHA256 ab.
    master_secret: hochentropisches Secret (z.B. os.urandom(32)), KEIN Hostname
    Längenpräfixe verhindern Kollisionen zwischen (index, nonce)-Paaren.
    """
    # FIX: Längentrennzeichen: len(index) als 2-Byte-Präfix
    msg = len(index).to_bytes(2, "big") + index + nonce
    return hmac.new(master_secret, msg, hashlib.sha256).hexdigest()[:HMAC_DERIVE_LENGTH]

def gen_id(pub_bytes: bytes, length: int = 32) -> str:
    """
    Erzeugt eine zufällige, vom Public Key abgeleitete Adresse
    und kürzt sie auf die gewünschte Länge.

    Kein Privileg- oder Dateizugriff nötig.
    """
    if length <= 0:
        raise ValueError("length muss > 0 sein")
    if len(pub_bytes) != ED25519_KEY_SIZE:
        raise ValueError("Ungültige Public-Key-Länge")

    nonce = secrets.token_bytes(16)  # sorgt für Zufälligkeit
    digest = hashlib.sha256(pub_bytes + nonce).hexdigest()

    return digest[:length]


if __name__ == "__main__":
    
    master_secret = secrets.token_bytes(32)   
    nonce = secrets.token_bytes(16)           


    
    priv, pub = load_or_create_keys(password)
    pub_bytes = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    print("Standard:", base_address(pub_bytes))
    # for i in range(5):
    #     addr = derive_address(master_secret, i.to_bytes(4, "big"), nonce)
    #     print(f"[{i}]", addr)