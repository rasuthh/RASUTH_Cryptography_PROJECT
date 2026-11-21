import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448


def load_certificate(path):
    data = Path(path).read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def load_crl(path):
    data = Path(path).read_bytes()
    try:
        return x509.load_pem_x509_crl(data)
    except ValueError:
        return x509.load_der_x509_crl(data)


def certificate_status(certificate, warning_days=30):
    now = datetime.now(timezone.utc)
    expiry = certificate.not_valid_after_utc
    days_left = (expiry - now).total_seconds() / 86400

    if days_left < 0:
        status = "EXPIRED"
    elif days_left <= warning_days:
        status = "EXPIRING_SOON"
    else:
        status = "VALID"

    return {
        "status": status,
        "expires_at": expiry.isoformat(),
        "days_left": round(days_left, 2),
        "serial_number": certificate.serial_number,
    }


def verify_crl_signature(crl, issuer_certificate):
    if crl.issuer != issuer_certificate.subject:
        raise ValueError("CRL issuer does not match the issuer certificate.")

    public_key = issuer_certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding.PKCS1v15(),
            crl.signature_hash_algorithm,
        )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            ec.ECDSA(crl.signature_hash_algorithm),
        )
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key.verify(crl.signature, crl.tbs_certlist_bytes)
    else:
        raise ValueError("Unsupported issuer public-key type.")


def check_revocation(certificate, crl, issuer_certificate):
    verify_crl_signature(crl, issuer_certificate)
    revoked = crl.get_revoked_certificate_by_serial_number(
        certificate.serial_number
    )
    return {
        "revoked": revoked is not None,
        "serial_number": certificate.serial_number,
        "crl_signature_valid": True,
    }


def run_certbot_renew(dry_run=False):
    command = ["certbot", "renew"]
    if dry_run:
        command.append("--dry-run")
    return subprocess.run(command, check=False).returncode


def main():
    parser = argparse.ArgumentParser(
        description="Basic PKI certificate lifecycle and CRL checker."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--certificate", required=True)

    crl_parser = subparsers.add_parser("check-crl")
    crl_parser.add_argument("--certificate", required=True)
    crl_parser.add_argument("--crl", required=True)
    crl_parser.add_argument("--issuer", required=True)

    renew_parser = subparsers.add_parser("renew")
    renew_parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    if args.command == "inspect":
        certificate = load_certificate(args.certificate)
        print(certificate_status(certificate))
    elif args.command == "check-crl":
        certificate = load_certificate(args.certificate)
        crl = load_crl(args.crl)
        issuer = load_certificate(args.issuer)
        result = check_revocation(certificate, crl, issuer)
        print(result)
        if result["revoked"]:
            raise SystemExit("Certificate is REVOKED.")
        print("Certificate is not listed as revoked.")
    elif args.command == "renew":
        code = run_certbot_renew(args.dry_run)
        if code != 0:
            raise SystemExit(code)
        print("Certbot renewal command completed successfully.")


if __name__ == "__main__":
    main()
