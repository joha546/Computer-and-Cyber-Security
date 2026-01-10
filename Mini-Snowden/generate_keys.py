from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

# Create server directory if it doesn't exist
os.makedirs('server/keys', exist_ok=True)

# 1. Generate X25519 key pair for key exchange
x25519_private_key = x25519.X25519PrivateKey.generate()
x25519_public_key = x25519_private_key.public_key()

# Serialize and save X25519 keys
with open("server/keys/server_x25519_private.pem", "wb") as f:
    f.write(x25519_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("server/keys/server_x25519_public.pem", "wb") as f:
    f.write(x25519_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# 2. Generate Ed25519 key pair for signing (authentication)
ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
ed25519_public_key = ed25519_private_key.public_key()

# Serialize and save Ed25519 keys
with open("server/keys/server_ed25519_private.pem", "wb") as f:
    f.write(ed25519_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("server/keys/server_ed25519_public.pem", "wb") as f:
    f.write(ed25519_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Print the public signing key for the client to use
with open("server/keys/server_ed25519_public.pem", "rb") as f:
    public_key_bytes = f.read()
    
print("--- SERVER IDENTITY (Ed25519 Public Key) ---")
print("Copy this key into the client code.")
print("=============================================")
print(public_key_bytes.decode('utf-8'))
print("=============================================")