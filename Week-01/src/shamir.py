import secrets

# AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
REDUCTION = 0x1B


def gf_multiply(a, b):
    """Multiply two bytes in GF(2^8)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return result


def gf_power(value, power):
    result = 1
    while power:
        if power & 1:
            result = gf_multiply(result, value)
        value = gf_multiply(value, value)
        power >>= 1
    return result


def gf_inverse(value):
    if value == 0:
        raise ValueError("Zero has no inverse in GF(2^8).")
    return gf_power(value, 254)


def split_secret(secret, total_shares=5, threshold=3):
    """Split bytes into shares; any threshold number can reconstruct them."""
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("Secret must be non-empty bytes.")
    if not (2 <= threshold <= total_shares <= 255):
        raise ValueError("Use 2 <= threshold <= total_shares <= 255.")

    shares = [(x, bytearray()) for x in range(1, total_shares + 1)]

    for secret_byte in secret:
        coefficients = [secret_byte] + [
            secrets.randbelow(256) for _ in range(threshold - 1)
        ]

        for x, share_data in shares:
            y = 0
            for coefficient in reversed(coefficients):
                y = gf_multiply(y, x) ^ coefficient
            share_data.append(y)

    return [(x, bytes(data)) for x, data in shares]


def combine_shares(shares, threshold=3):
    """Rebuild the secret using at least threshold distinct shares."""
    if len(shares) < threshold:
        raise ValueError(f"At least {threshold} shares are required.")

    selected = shares[:threshold]
    x_values = [share[0] for share in selected]

    if len(set(x_values)) != len(x_values):
        raise ValueError("Share coordinates must be different.")
    if any(not 1 <= x <= 255 for x in x_values):
        raise ValueError("Share coordinates must be between 1 and 255.")

    lengths = {len(data) for _, data in selected}
    if len(lengths) != 1 or not lengths or next(iter(lengths)) == 0:
        raise ValueError("Shares must have equal, non-zero lengths.")

    secret = bytearray()
    for position in range(next(iter(lengths))):
        value = 0

        for i, (x_i, data_i) in enumerate(selected):
            numerator = 1
            denominator = 1

            for j, (x_j, _) in enumerate(selected):
                if i != j:
                    numerator = gf_multiply(numerator, x_j)
                    denominator = gf_multiply(denominator, x_i ^ x_j)

            lagrange = gf_multiply(numerator, gf_inverse(denominator))
            value ^= gf_multiply(data_i[position], lagrange)

        secret.append(value)

    return bytes(secret)
