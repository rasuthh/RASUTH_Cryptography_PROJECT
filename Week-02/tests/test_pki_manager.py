from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.pki_manager import certificate_status, check_revocation


def make_test_certificates(tmp_path, revoke=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(timezone.utc)

    issuer = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(100)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "service.test")]))
        .issuer_name(name)
        .public_key(leaf_key.public_key())
        .serial_number(200)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=60))
        .sign(key, hashes.SHA256())
    )

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=1))
    )
    if revoke:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.serial_number)
            .revocation_date(now - timedelta(minutes=1))
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(key, hashes.SHA256())

    return leaf, issuer, crl


def test_valid_certificate_status():
    leaf, _, _ = make_test_certificates(None)
    assert certificate_status(leaf)["status"] == "VALID"


def test_crl_reports_not_revoked():
    leaf, issuer, crl = make_test_certificates(None, revoke=False)
    result = check_revocation(leaf, crl, issuer)
    assert result["crl_signature_valid"] is True
    assert result["revoked"] is False


def test_crl_detects_revoked_certificate():
    leaf, issuer, crl = make_test_certificates(None, revoke=True)
    result = check_revocation(leaf, crl, issuer)
    assert result["revoked"] is True


def test_crl_with_wrong_issuer_is_rejected():
    import pytest
    leaf, issuer, crl = make_test_certificates(None, revoke=False)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
    now = datetime.now(timezone.utc)
    other_issuer = (
        x509.CertificateBuilder()
        .subject_name(other_name)
        .issuer_name(other_name)
        .public_key(other_key.public_key())
        .serial_number(999)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(other_key, hashes.SHA256())
    )
    with pytest.raises(ValueError):
        check_revocation(leaf, crl, other_issuer)
