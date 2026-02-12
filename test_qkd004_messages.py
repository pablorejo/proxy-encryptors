import unittest

from qkd004_messages import (
    Destination,
    QoS,
    QKDCloseRequest,
    QKDGetKeyRequest,
    QKDGetKeyResponse,
    QKDOpenRequest,
    QKDOpenResponse,
    Status,
    StatusCode,
    decode_message,
    encode_message,
)


def make_key_handle() -> bytes:
    return bytes(range(64))


class QKDMessagesTest(unittest.TestCase):
    def test_open_request_roundtrip(self) -> None:
        msg = QKDOpenRequest(
            destination=Destination(ip="127.0.0.1", port=9000),
            qos=QoS(key_size_bytes=32, min_bitrate_bps=1_000_000, timeout_ms=500),
            key_handle=make_key_handle(),
        )
        raw = encode_message(msg)
        parsed = decode_message(raw)
        self.assertEqual(msg, parsed)

    def test_open_response_roundtrip_without_key_handle(self) -> None:
        msg = QKDOpenResponse(status=Status(StatusCode.OK, "created"))
        raw = encode_message(msg)
        parsed = decode_message(raw)
        self.assertEqual(msg, parsed)

    def test_get_key_roundtrip(self) -> None:
        request = QKDGetKeyRequest(key_handle=make_key_handle(), key_size_bytes=64)
        request_raw = encode_message(request)
        request_parsed = decode_message(request_raw)
        self.assertEqual(request, request_parsed)

        response = QKDGetKeyResponse(
            status=Status(StatusCode.OK),
            key_buffer=b"super-secret-key-bytes",
        )
        response_raw = encode_message(response)
        response_parsed = decode_message(response_raw)
        self.assertEqual(response, response_parsed)

    def test_invalid_key_handle_size_raises(self) -> None:
        with self.assertRaises(ValueError):
            QKDCloseRequest(key_handle=b"too-short")


if __name__ == "__main__":
    unittest.main()

