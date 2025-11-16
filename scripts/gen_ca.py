#!/usr/bin/env python3
"""
Generate a Root CA (RSA 2048) and self-signed certificate.
Writes:
  certs/ca.key.pem
  certs/ca.cert.pem
"""
import argparse, os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--name', required=True, help='CA Common Name')
    p.add_argument('--out-dir', default='certs', help='output dir')
    args = p.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.name)])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(minutes=5))
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    with open(os.path.join(args.out_dir, 'ca.key.pem'), 'wb') as f:
        f.write(key_pem)
    with open(os.path.join(args.out_dir, 'ca.cert.pem'), 'wb') as f:
        f.write(cert_pem)

    print("Wrote CA key + cert to", args.out_dir)

if __name__ == '__main__':
    main()
