# Week 3 — Oblivious RAM (ORAM) Architecture for Access Pattern Hiding in Cloud Storage

**Student:** Rasuth Gowda  
**USN:** 23BCAR0050

## Problem

A cloud storage provider may not be able to read encrypted file contents, but it can still observe which storage locations are accessed. Repeated access patterns can reveal user activity.

## Solution

This project demonstrates a simplified Path ORAM design:

- Data blocks are encrypted with AES-GCM.
- Each logical block is assigned a random leaf in a binary tree.
- A read or write fetches the full path from the root to the assigned leaf.
- The block is assigned a new random leaf after access.
- Blocks are moved from the temporary stash back into eligible path buckets.
- The access log records tree paths, not logical block IDs.

## Files

- `src/path_oram.py` — simplified Path ORAM implementation
- `src/main.py` — example storage operations
- `tests/test_path_oram.py` — read/write and access-pattern tests

## Setup and run

```bash
python -m pip install -r requirements.txt
python -m src.main
python -m pytest
```

## Important note

This is a learning prototype, not a production ORAM implementation. A production design needs a formal security analysis, carefully bounded stash behavior, constant-size bucket serialization, network-level padding, and side-channel review.
