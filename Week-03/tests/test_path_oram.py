
import pytest
from src.path_oram import PathORAM


def make_oram():
    return PathORAM({
        "a": b"alpha",
        "b": b"bravo",
        "c": b"charlie",
    }, bucket_size=4, tree_depth=3)


def test_read_returns_original_value():
    oram = make_oram()
    assert oram.access("a") == b"alpha"


def test_write_then_read_returns_new_value():
    oram = make_oram()
    oram.access("b", b"new value")
    assert oram.access("b") == b"new value"


def test_each_access_reads_a_full_path():
    oram = make_oram()
    oram.access("a")
    oram.access("c")
    trace = oram.get_access_trace()
    assert len(trace) == 2
    assert len(trace[0]) == 4
    assert len(trace[1]) == 4


def test_unknown_block_is_rejected():
    oram = make_oram()
    with pytest.raises(KeyError):
        oram.access("not-present")


def test_non_byte_write_is_rejected():
    oram = make_oram()
    with pytest.raises(ValueError):
        oram.access("a", "plain text")


def test_modified_ciphertext_is_rejected():
    oram = PathORAM({"secret": b"protected data"}, bucket_size=4, tree_depth=2)
    entries = list(oram.stash)
    for bucket in oram.tree.values():
        entries.extend(bucket)
    target = next(entry for entry in entries if entry["block_id"] == "secret")
    changed = bytearray(target["encrypted"])
    changed[-1] ^= 1
    target["encrypted"] = bytes(changed)
    with pytest.raises(Exception):
        oram.access("secret")
