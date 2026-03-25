# crypto_utils.py
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def derive_key(password: str, salt: bytes) -> bytes:
    """从密码 + salt 派生 32 字节 AES-256 密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(data: bytes, password: str) -> tuple[bytes, bytes, bytes]:
    """
    加密数据，返回 (salt, nonce, ciphertext_with_tag)
    ciphertext_with_tag = nonce(12B) + ciphertext + auth_tag(16B) 已由 AESGCM 处理
    但为清晰，我们显式分离 salt/nonce/ciphertext/tag
    """
    salt = os.urandom(16)          # 每次加密随机 salt
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)         # GCM 推荐 12 字节 nonce
    ciphertext = aesgcm.encrypt(nonce, data, None)  # ciphertext = actual_ciphertext + 16B auth_tag
    return salt, nonce, ciphertext

def decrypt_file(salt: bytes, nonce: bytes, ciphertext_with_tag: bytes, password: str) -> bytes:
    """解密，失败则抛出 InvalidTag"""
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)