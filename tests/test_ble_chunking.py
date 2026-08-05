import pytest

from siros_verifier.ble import (
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    Reassembler,
    chunk_message,
    negotiate_chunk_size,
)


def test_chunk_message_single_chunk_when_it_fits():
    chunks = chunk_message(b"hello", max_chunk_size=20)
    assert chunks == [b"\x00hello"]


def test_chunk_message_splits_across_multiple_chunks():
    message = bytes(range(10))
    chunks = chunk_message(message, max_chunk_size=4)  # 3 payload bytes/chunk
    assert chunks == [
        b"\x01" + bytes([0, 1, 2]),
        b"\x01" + bytes([3, 4, 5]),
        b"\x01" + bytes([6, 7, 8]),
        b"\x00" + bytes([9]),
    ]


def test_chunk_message_empty_message_is_a_single_last_chunk():
    assert chunk_message(b"", max_chunk_size=20) == [b"\x00"]


def test_chunk_message_rejects_degenerate_chunk_size():
    with pytest.raises(ValueError):
        chunk_message(b"data", max_chunk_size=1)


def test_reassembler_roundtrips_chunked_message():
    message = bytes(range(50))
    reassembler = Reassembler()
    result = None
    for chunk in chunk_message(message, max_chunk_size=7):
        result = reassembler.feed(chunk)
    assert result == message


def test_reassembler_returns_none_until_last_chunk():
    reassembler = Reassembler()
    assert reassembler.feed(b"\x01abc") is None
    assert reassembler.feed(b"\x00def") == b"abcdef"


@pytest.mark.parametrize(
    "mtu,expected",
    [
        (23, MIN_CHUNK_SIZE),  # default BLE MTU - 3 = 20, already at the floor
        (517, MAX_CHUNK_SIZE),  # max negotiated MTU - 3 = 514, clamped to 512
        (100, 97),
    ],
)
def test_negotiate_chunk_size(mtu, expected):
    assert negotiate_chunk_size(mtu) == expected
