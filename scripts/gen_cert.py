#!/usr/bin/env python3
"""
Generate an RSA key + certificate signed by the Root CA (created by gen_ca.py).
Usage:
  python scripts/gen_cert.py --cn server.local --out certs/server
"""
import argparse, os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def load_ca(ca_key_path='certs/ca.key.pem', ca_cert_path='certs/ca.cert.pem'):
    with open(ca_key_path,'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path,'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--cn', required=True)
    p.add_argument('--out', required=True, help='output path prefix (e.g. certs/server)')
    args = p.parse_args()
    os.makedirs(os.path.dirname(args.out) or 'certs', exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.cn)]))
           .sign(key, hashes.SHA256()))

    ca_key, ca_cert = load_ca()
    cert = (x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(minutes=5))
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(args.cn)]), critical=False)
            .sign(ca_key, hashes.SHA256()))

    key_pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    with open(f'{args.out}.key.pem','wb') as f: f.write(key_pem)
    with open(f'{args.out}.cert.pem','wb') as f: f.write(cert_pem)

    print("Wrote", f'{args.out}.key.pem', f'{args.out}.cert.pem')

if __name__ == '__main__':
    main()
