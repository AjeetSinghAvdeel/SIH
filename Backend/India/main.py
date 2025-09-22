import os
import hashlib
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def generate_keys():
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("🔑 RSA key pair generated.")


def wipe_file(filepath, passes=3):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"{filepath} not found")

    file_size = os.path.getsize(filepath)
    with open(filepath, "r+b") as f:
        for p in range(passes):
            f.seek(0)
            random_data = os.urandom(file_size)
            f.write(random_data)
            f.flush()
            os.fsync(f.fileno())
    os.remove(filepath)
    return True


def sign_data(data: str):
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        data.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature.hex()


def generate_certificate(device_name, method, passes, output_dir="certs"):
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    cert_data = {
        "device_name": device_name,
        "wipe_method": method,
        "passes": passes,
        "timestamp": timestamp,
        "hash": hashlib.sha256(f"{device_name}{timestamp}".encode()).hexdigest()
    }

    # Sign certificate
    signature = sign_data(json.dumps(cert_data, sort_keys=True))
    cert_data["signature"] = signature

    # Save JSON
    json_path = os.path.join(output_dir, f"{device_name}_certificate.json")
    with open(json_path, "w") as jf:
        json.dump(cert_data, jf, indent=4)

    # Save PDF
    pdf_path = os.path.join(output_dir, f"{device_name}_certificate.pdf")
    c = canvas.Canvas(pdf_path, pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(50, 750, "Secure Wipe Certificate")
    c.drawString(50, 720, f"Device: {cert_data['device_name']}")
    c.drawString(50, 700, f"Wipe Method: {cert_data['wipe_method']}")
    c.drawString(50, 680, f"Passes: {cert_data['passes']}")
    c.drawString(50, 660, f"Timestamp: {cert_data['timestamp']}")
    c.drawString(50, 640, f"Unique Hash: {cert_data['hash']}")
    c.drawString(50, 620, f"Signature: {signature[:50]}...")  # shortened in PDF
    c.save()

    return json_path, pdf_path


def verify_certificate(json_file):
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open(json_file, "r") as jf:
        cert_data = json.load(jf)

    signature = bytes.fromhex(cert_data["signature"])
    data_str = json.dumps({k: cert_data[k] for k in cert_data if k != "signature"}, sort_keys=True)

    try:
        public_key.verify(
            signature,
            data_str.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


if __name__ == "__main__":
    
    generate_keys()

    test_file = "test_data.bin"
    if not os.path.exists(test_file):
        with open(test_file, "wb") as f:
            f.write(os.urandom(1 * 1024 * 1024))  # 1 MB demo file

    print("Wiping file securely...")
    wipe_file(test_file, passes=1)

    print("Generating signed certificate...")
    json_cert, pdf_cert = generate_certificate("TestDisk1", "Random Overwrite", 1)
    print(f"✅ Certificates created:\n{json_cert}\n{pdf_cert}")

    print("Verifying certificate...")
    if verify_certificate(json_cert):
        print("✅ Certificate is valid and untampered.")
    else:
        print("❌ Certificate verification failed.")
