import pytest
from src.shamir import split_secret, combine_shares


def test_any_three_shares_reconstruct_secret():
    secret = b"my sample 256-bit master key material"
    shares = split_secret(secret, 5, 3)
    assert combine_shares([shares[0], shares[2], shares[4]], 3) == secret
    assert combine_shares([shares[1], shares[2], shares[3]], 3) == secret


def test_two_shares_are_rejected():
    shares = split_secret(b"secret key", 5, 3)
    with pytest.raises(ValueError):
        combine_shares(shares[:2], 3)


def test_duplicate_share_coordinates_are_rejected():
    shares = split_secret(b"secret key", 5, 3)
    with pytest.raises(ValueError):
        combine_shares([shares[0], shares[0], shares[2]], 3)


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError):
        split_secret(b"secret", 5, 6)
