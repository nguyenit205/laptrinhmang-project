"""
HYBRID ENCRYPTION: RSA + AES + Password
- File được mã hóa bằng AES-256 (nhanh, phù hợp file lớn)
- AES key được mã hóa bằng RSA-2048 (bảo mật cao)
- RSA private key được bảo vệ bằng password (PBKDF2)
"""
import os
import json
import uuid
import datetime
import qrcode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Giới hạn file 50MB
MAX_FILE_SIZE = 50 * 1024 * 1024

os.makedirs("encrypted", exist_ok=True)
os.makedirs("qrcodes", exist_ok=True)
os.makedirs("keys", exist_ok=True)


# ============== RSA KEY MANAGEMENT (Password-Protected) ==============

def generate_password_protected_keypair(password: str, user_id: str):
    """
    Tạo RSA keypair và mã hóa private key bằng password
    Returns: (public_key_path, encrypted_private_key_path)
    """
    # Check if already exists
    pub_path = os.path.join("keys", f"{user_id}_public.pem")
    priv_path = os.path.join("keys", f"{user_id}_private.enc")
    
    if os.path.exists(pub_path) and os.path.exists(priv_path):
        print(f"✅ RSA keypair already exists: {user_id}")
        return pub_path, priv_path
    
    print(f"🔑 Generating RSA keypair for: {user_id}")
    
    # Generate RSA-2048 keypair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Derive encryption key từ password
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Encrypt private key bằng AES-256
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding (AES requires block size = 16)
    pad_len = 16 - (len(private_pem) % 16)
    private_pem_padded = private_pem + bytes([pad_len]) * pad_len
    
    encrypted_private = encryptor.update(private_pem_padded) + encryptor.finalize()
    
    # Save encrypted private key (salt + iv + encrypted_data)
    with open(priv_path, "wb") as f:
        f.write(salt)  # 16 bytes
        f.write(iv)    # 16 bytes
        f.write(encrypted_private)
    
    # Save public key (plain)
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    
    print(f"✅ RSA keypair generated: {user_id}")
    return pub_path, priv_path


def load_private_key_with_password(user_id: str, password: str):
    """
    Load và decrypt RSA private key bằng password
    Raises ValueError nếu password sai
    """
    priv_path = os.path.join("keys", f"{user_id}_private.enc")
    if not os.path.exists(priv_path):
        raise FileNotFoundError(f"Private key not found: {priv_path}")
    
    with open(priv_path, "rb") as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_private = f.read()
    
    # Derive key từ password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    
    # Decrypt private key
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        private_pem_padded = decryptor.update(encrypted_private) + decryptor.finalize()
        
        # Remove padding
        pad_len = private_pem_padded[-1]
        private_pem = private_pem_padded[:-pad_len]
        
        # Load RSA private key
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,
            backend=default_backend()
        )
        return private_key
    
    except Exception as e:
        raise ValueError(f"Wrong password or corrupted key: {e}")


def load_public_key(user_id: str):
    """Load RSA public key (không cần password)"""
    pub_path = os.path.join("keys", f"{user_id}_public.pem")
    if not os.path.exists(pub_path):
        raise FileNotFoundError(f"Public key not found: {pub_path}")
    
    with open(pub_path, "rb") as f:
        pub_pem = f.read()
    
    public_key = serialization.load_pem_public_key(
        pub_pem,
        backend=default_backend()
    )
    return public_key


# ============== HYBRID ENCRYPTION (AES + RSA) ==============

def encrypt_file_hybrid(file_path: str, user_id: str) -> tuple[str, str]:
    """
    Mã hóa file bằng Hybrid Encryption:
    1. Random AES-256 key
    2. Encrypt file với AES-GCM (authenticated encryption)
    3. Encrypt AES key bằng RSA public key
    4. Save: [encrypted_aes_key_len(4)] [encrypted_aes_key] [nonce(12)] [tag(16)] [encrypted_file]
    
    Returns: (file_id, encrypted_path)
    """
    # Kiểm tra file
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, "rb") as f:
        file_data = f.read()
    
    if len(file_data) > MAX_FILE_SIZE:
        raise ValueError(f"File quá lớn ({len(file_data)} bytes). Max: {MAX_FILE_SIZE}")
    
    # Step 1: Generate random AES-256 key
    aes_key = os.urandom(32)  # 256 bits
    
    # Step 2: Encrypt file bằng AES-GCM
    nonce = os.urandom(12)  # GCM nonce
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encrypted_file = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag  # Authentication tag (16 bytes)
    
    # Step 3: Encrypt AES key bằng RSA public key
    public_key = load_public_key(user_id)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Step 4: Save encrypted file
    file_id = str(uuid.uuid4())
    enc_path = os.path.join("encrypted", file_id + ".bin")
    
    with open(enc_path, "wb") as f:
        # Write encrypted AES key length (4 bytes)
        f.write(len(encrypted_aes_key).to_bytes(4, 'big'))
        # Write encrypted AES key (256 bytes for RSA-2048)
        f.write(encrypted_aes_key)
        # Write nonce (12 bytes)
        f.write(nonce)
        # Write tag (16 bytes)
        f.write(tag)
        # Write encrypted file
        f.write(encrypted_file)
    
    print(f"🔒 Hybrid encrypted: {file_id}")
    return file_id, enc_path


def build_token(file_id: str, filename: str, user_id: str, sender: str = "Anonymous") -> str:
    """
    Build token (metadata) để nhúng vào QR code
    """
    token_obj = {
        "file_id": file_id,
        "filename": filename,
        "user_id": user_id,  # Owner của RSA keypair
        "from": sender,
        "ts": datetime.datetime.utcnow().isoformat(),
        "hint": "Password required to decrypt",
    }
    return json.dumps(token_obj)


def generate_qr(token_str: str, file_id: str):
    """Generate QR code từ token"""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2,
    )
    qr.add_data(token_str)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    qr_path = os.path.join("qrcodes", file_id + ".png")
    img.save(qr_path)
    
    print(f"📱 QR code generated: {qr_path}")
    return qr_path, img


def decrypt_file_hybrid(token_str: str, password: str) -> tuple[bytes, str]:
    """
    Giải mã file bằng Hybrid Decryption:
    1. Parse token → lấy file_id, user_id
    2. Nhập password → load RSA private key
    3. Decrypt AES key bằng RSA private key
    4. Decrypt file bằng AES key
    
    Returns: (file_data, filename)
    """
    # Parse token
    try:
        obj = json.loads(token_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid token: {e}")
    
    file_id = obj.get("file_id")
    user_id = obj.get("user_id")
    filename = obj.get("filename", "output")
    
    if not file_id or not user_id:
        raise ValueError("Token missing required fields")
    
    # Read encrypted file
    enc_path = os.path.join("encrypted", file_id + ".bin")
    if not os.path.exists(enc_path):
        raise FileNotFoundError(f"Encrypted file not found: {enc_path}")
    
    with open(enc_path, "rb") as f:
        # Read encrypted AES key length
        key_len = int.from_bytes(f.read(4), 'big')
        # Read encrypted AES key
        encrypted_aes_key = f.read(key_len)
        # Read nonce (12 bytes)
        nonce = f.read(12)
        # Read tag (16 bytes)
        tag = f.read(16)
        # Read encrypted file
        encrypted_file = f.read()
    
    # Load RSA private key bằng password
    try:
        private_key = load_private_key_with_password(user_id, password)
    except ValueError:
        raise ValueError("Wrong password!")
    except FileNotFoundError:
        raise ValueError(f"Private key not found for user: {user_id}")
    
    # Decrypt AES key bằng RSA private key
    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"Failed to decrypt AES key: {e}")
    
    # Decrypt file bằng AES-GCM
    try:
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        file_data = decryptor.update(encrypted_file) + decryptor.finalize()
    except Exception as e:
        raise ValueError(f"Failed to decrypt file: {e}")
    
    print(f"🔓 Hybrid decrypted: {filename}")
    return file_data, filename


# ============== HELPER ==============

def check_file_size(path: str) -> tuple[bool, int]:
    """Check file size"""
    try:
        size = os.path.getsize(path)
        return (size <= MAX_FILE_SIZE, size)
    except OSError as e:
        raise OSError(f"Cannot check file size: {e}")