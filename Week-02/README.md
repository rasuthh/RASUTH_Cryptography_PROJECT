# Week 2 — Automated PKI Certificate Lifecycle Management with ACME and CRL Checking

**Student:** Rasuth Gowda  
**USN:** 23BCAR0050

## Problem

Certificates can expire or be revoked. If a service does not renew certificates and check revocation status, users may connect to an expired or untrusted service.

## Solution

This Python project provides two checks:

1. It reads an X.509 certificate and reports whether it is expired or close to expiry.
2. It checks a Certificate Revocation List (CRL), verifies the CRL signature using the issuer certificate, and checks whether the certificate serial number is revoked.

It also provides a Certbot command to run an ACME renewal or a safe ACME staging dry run. Certbot must already be configured for a domain before renewal can work.

## Files

- `src/pki_manager.py` — certificate checks and Certbot ACME renewal command
- `tests/test_pki_manager.py` — offline certificate and CRL tests

## Setup and run

```bash
python -m pip install -r requirements.txt
python -m src.pki_manager --help
python -m pytest
```

Check a certificate:

```bash
python -m src.pki_manager inspect --certificate certificate.pem
```

Check a certificate against a local CRL and issuer certificate:

```bash
python -m src.pki_manager check-crl --certificate certificate.pem --crl issuer.crl --issuer issuer.pem
```

Test an existing Certbot ACME configuration without making a live renewal:

```bash
python -m src.pki_manager renew --dry-run
```

Run a real renewal only after Certbot is configured:

```bash
python -m src.pki_manager renew
```

## Important note

The tests generate certificates locally and do not contact a certificate authority. The Certbot command is the ACME integration point. A production deployment must also manage private-key permissions, renewal hooks, monitoring, and trusted CRL distribution.
