import secrets

# Genererer en sikker secret key med 32 bytes (256 bits) entropi
secret_key = secrets.token_hex(32)
print(f"Generated Secret Key: {secret_key}") 