# firmar_documento.py
# Simula el proceso realizado por el autor o desarrollador para firmar un documento.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- 1. Generar un par de claves RSA ---
print("1. Generando par de claves RSA...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048, # 2048 bits es el tamaño estándar de seguridad
    backend=default_backend()
)
public_key = private_key.public_key()

# Guardar la clave pública (Esta es la que se distribuye)
with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Guardar la clave privada (¡¡ESTA DEBE PERMANECER SECRETA!!)
# La guardamos sin cifrar solo para este ejemplo práctico.
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() 
    ))
print("   Claves RSA (public_key.pem y private_key.pem) generadas.")

# --- 2. Crear el archivo de texto a firmar ---
document_content = b"Este es el documento que debe ser protegido contra cualquier alteracion. Version 1.0."
with open("documento.txt", "wb") as f:
    f.write(document_content)
print("\n2. Archivo 'documento.txt' creado con el contenido a firmar.")

# --- 3. Calcular el hash del documento ---
hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
hasher.update(document_content)
digest = hasher.finalize()
print(f"   Hash SHA256 calculado (Resumen): {digest[:10].hex()}...")

# --- 4. Crear la firma digital con la clave privada ---
# La clave privada "cifra" el hash, creando la firma
signature = private_key.sign(
    digest,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH # PSS padding para seguridad en la firma
    ),
    hashes.SHA256()
)

# Guardar la firma digital
with open("documento.txt.sig", "wb") as f:
    f.write(signature)
print("\n3. Firma digital creada y guardada en 'documento.txt.sig'.")

print("\n--- PROCESO DE FIRMA COMPLETADO. Archivos listos para distribución. ---")