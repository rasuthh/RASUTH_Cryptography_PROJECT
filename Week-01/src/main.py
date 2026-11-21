from src.shamir import split_secret, combine_shares


def main():
    master_key = b"RASUTH-GOWDA-256-BIT-KEY-0000000"
    shares = split_secret(master_key, total_shares=5, threshold=3)

    print("Master key split into 5 shares.")
    for number, (x, data) in enumerate(shares, start=1):
        print(f"Share {number}: x={x}, data={data.hex()}")

    recovered_key = combine_shares([shares[0], shares[2], shares[4]], threshold=3)
    print("\nReconstruction successful:", recovered_key == master_key)


if __name__ == "__main__":
    main()
