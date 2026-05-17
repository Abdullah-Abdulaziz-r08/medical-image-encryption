import numpy as np
import hashlib
import struct
from PIL import Image
import io


def generate_key(img_array, secret_key, r=3.99):
    """
    توليد مفتاح التشفير من الصورة والسيكرت كي
    نفس منطق كود MATLAB بالضبط
    """
    # حساب SHA-256 للصورة
    img_bytes = img_array.flatten().tobytes()
    sha256_hash = hashlib.sha256(img_bytes).digest()

    # أخذ أول 8 bytes وتحويلها لرقم
    hash_num = struct.unpack('>Q', sha256_hash[:8])[0]

    # دمج الهاش مع السيكرت كي لتوليد نقطة البداية
    x0 = ((hash_num / (2**64)) + secret_key) % 1.0
    if x0 == 0:
        x0 = 0.357

    # توليد Logistic Map (Chaos)
    N = img_array.size
    chaos = np.zeros(N)
    chaos[0] = x0
    for i in range(1, N):
        chaos[i] = r * chaos[i-1] * (1 - chaos[i-1])

    # ترتيب الـ Permutation
    perm_idx = np.argsort(chaos)

    # مفتاح الـ XOR
    key = (np.floor(chaos * 1e14) % 256).astype(np.uint8)

    return perm_idx, key


def encrypt(img_array, secret_key):
    """
    تشفير الصورة - مرحلتين:
    1. Permutation: خلط البكسلات
    2. Diffusion: XOR تراكمي
    """
    img_array = img_array.astype(np.uint8)
    shape = img_array.shape
    N = img_array.size

    perm_idx, key = generate_key(img_array, secret_key)

    # المرحلة 1: Permutation
    flat = img_array.flatten()
    permuted = flat[perm_idx]

    # المرحلة 2: Diffusion
    encrypted = np.zeros(N, dtype=np.uint8)
    encrypted[0] = int(permuted[0]) ^ int(key[0])
    for i in range(1, N):
        encrypted[i] = int(permuted[i]) ^ int(key[i]) ^ int(encrypted[i-1])

    return encrypted.reshape(shape)


def decrypt(encrypted_array, img_hash_hex, secret_key):
    """
    فك تشفير الصورة باستخدام الـ Hash المخزّن في قاعدة البيانات
    """
    encrypted_array = encrypted_array.astype(np.uint8)
    shape = encrypted_array.shape
    N = encrypted_array.size

    # إعادة توليد نفس المفتاح من الـ Hash
    sha256_bytes = bytes.fromhex(img_hash_hex)
    hash_num = struct.unpack('>Q', sha256_bytes[:8])[0]

    x0 = ((hash_num / (2**64)) + secret_key) % 1.0
    if x0 == 0:
        x0 = 0.357

    r = 3.99
    chaos = np.zeros(N)
    chaos[0] = x0
    for i in range(1, N):
        chaos[i] = r * chaos[i-1] * (1 - chaos[i-1])

    perm_idx = np.argsort(chaos)
    key = (np.floor(chaos * 1e14) % 256).astype(np.uint8)

    flat = encrypted_array.flatten()

    # عكس Diffusion
    decrypted_diff = np.zeros(N, dtype=np.uint8)
    decrypted_diff[0] = int(flat[0]) ^ int(key[0])
    for i in range(1, N):
        decrypted_diff[i] = int(flat[i]) ^ int(key[i]) ^ int(flat[i-1])

    # عكس Permutation
    inv_perm = np.zeros(N, dtype=np.int64)
    inv_perm[perm_idx] = np.arange(N)
    result = decrypted_diff[inv_perm]

    return result.reshape(shape)


def compute_hash(img_array):
    """حساب SHA-256 للصورة"""
    return hashlib.sha256(img_array.astype(np.uint8).flatten().tobytes()).hexdigest()


def bytes_to_array(image_bytes):
    """تحويل bytes الصورة إلى numpy array"""
    img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    return np.array(img, dtype=np.uint8)


def array_to_bytes(img_array):
    """تحويل numpy array إلى bytes PNG"""
    img = Image.fromarray(img_array.astype(np.uint8))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf.read()