from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import hashlib
import os

# Dosya yolu (Windows için)
file_path = r'C:\Users\mamtr\Downloads\import_os6.py'  # Yolu kendi bilgisayarınıza göre ayarlayın

# Anahtar çiftini oluştur
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Özel anahtarın dosyaya kaydedilmesi
    with open('private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Genel anahtarın dosyaya kaydedilmesi
    public_key = private_key.public_key()
    with open('public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Dosyanın özetini hesapla
def calculate_hash(file_path):
    hash_obj = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_obj.update(chunk)
    return hash_obj.digest()

# Mesaj özetini imzala
def sign_message(message_hash, private_key_path):
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    signature = private_key.sign(
        message_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

# İmzanın doğruluğunu kontrol et
def verify_signature(message_hash, signature, public_key_path):
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    try:
        public_key.verify(
            signature,
            message_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

# Anahtar çiftini oluştur
generate_keys()

# Dosya özetini hesapla
message_hash = calculate_hash(file_path)

# İmzayı oluştur
signature = sign_message(message_hash, 'private_key.pem')

# İmzayı dosyaya kaydet
with open('signature.sig', 'wb') as f:
    f.write(signature)

# İmzanın doğruluğunu kontrol et
is_valid = verify_signature(message_hash, signature, 'public_key.pem')
print(f'İmza geçerli mi? {is_valid}')
