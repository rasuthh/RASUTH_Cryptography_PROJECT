
from src.path_oram import PathORAM


def main():
    storage = PathORAM({
        "file-1": b"student assignment",
        "file-2": b"project report",
        "file-3": b"private notes",
    })

    print("Read file-1:", storage.access("file-1").decode())
    storage.access("file-2", b"updated project report")
    print("Read updated file-2:", storage.access("file-2").decode())
    print("Recorded tree paths:", storage.get_access_trace())


if __name__ == "__main__":
    main()
