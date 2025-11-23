# verificar_documento.py
# Simula la verificación realizada por el receptor o la aplicación al iniciar.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- 1. Cargar la clave pública y la firma ---
print("1. Cargando archivos necesarios para la verificación...")
try:
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    with open("documento.txt.sig", "rb") as f:
        signature = f.read()
    with open("documento.txt", "rb") as f:
        document_data = f.read()
    print("   Archivos cargados correctamente.")
except FileNotFoundError:
    print("Error: Asegúrese de ejecutar 'firmar_documento.py' primero y de no haber borrado los archivos.")
    exit()

# --- 2. Recalcular el hash del documento recibido ---
hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
hasher.update(document_data)
recalculated_digest = hasher.finalize()
print("\n2. Hash del documento recalculado.")

# --- 3. Verificar la firma usando la clave pública ---
print("3. Ejecutando la verificación de la firma...")
try:
    public_key.verify(
        signature,
        recalculated_digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Si la verificación es exitosa, se crea el nuevo archivo de texto.
    output_filename = "documento_verificado.txt"
    with open(output_filename, "wb") as f:
        f.write(document_data)
        
    print(f"\n VERIFICACIÓN EXITOSA:")
    print(f"   El documento es **AUTÉNTICO** y su **INTEGRIDAD** está garantizada.")
    print(f"   → El contenido íntegro ha sido guardado en: {output_filename}")
    
except Exception:
    print("\n FALLO DE VERIFICACIÓN:")
    print("   La firma es inválida. El documento ha sido alterado o la firma no corresponde al autor.")
    
print("\n--- PROCESO DE VERIFICACIÓN RSA COMPLETADO ---")