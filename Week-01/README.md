# Week 1 — Shamir's Secret Sharing Scheme

**Student:** Rasuth Gowda  
**USN:** 23BCAR0050

## Problem

If one person keeps the only copy of a master encryption key, losing that copy can cause permanent data loss. Giving the full key to many people creates an insider risk.

## Solution

This program splits a 256-bit key into **5 shares**. Any **3 shares** can rebuild the original key. The program uses Shamir's Secret Sharing over the AES finite field, GF(2^8), one byte of the key at a time.

## Files

- `src/shamir.py` — split and reconstruct functions
- `src/main.py` — example run
- `tests/test_shamir.py` — normal and invalid-input tests

## Setup and run

```bash
python -m pip install -r requirements.txt
python -m src.main
python -m pytest
```

## Expected result

The example creates five shares, reconstructs the key using three shares, and confirms that the reconstructed key matches the original.

## Important note

This is an educational implementation. It demonstrates threshold splitting and reconstruction; do not use it as a production key-management system without an independent security review.
