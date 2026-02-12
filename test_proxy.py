import json
import os
import unittest
from unittest.mock import patch

from proxy import QKDProxyService
from qkd004_messages import (
    Destination,
    QoS,
    QKDCloseRequest,
    QKDConnectBlockingRequest,
    QKDConnectNonBlockRequest,
    QKDGetKeyRequest,
    QKDOpenRequest,
    QKDOpenResponse,
    Status,
    StatusCode,
    decode_message,
    encode_message,
)


class ProxyServiceTest(unittest.TestCase):
    def test_full_flow(self) -> None:
        service = QKDProxyService()

        open_request = QKDOpenRequest(
            destination=Destination(ip="127.0.0.1", port=9000),
            qos=QoS(key_size_bytes=32, min_bitrate_bps=1000, timeout_ms=100),
        )
        open_response_raw = service.handle_raw_message(encode_message(open_request))
        open_response = decode_message(open_response_raw)
        self.assertIsInstance(open_response, QKDOpenResponse)
        self.assertEqual(open_response.status.code, StatusCode.OK)
        self.assertIsNotNone(open_response.key_handle)
        key_handle = open_response.key_handle
        assert key_handle is not None

        connect_request = QKDConnectNonBlockRequest(key_handle=key_handle)
        connect_response = decode_message(
            service.handle_raw_message(encode_message(connect_request))
        )
        self.assertEqual(connect_response.status.code, StatusCode.OK)
        self.assertTrue(connect_response.synchronized)

        get_key_request = QKDGetKeyRequest(key_handle=key_handle, key_size_bytes=48)
        get_key_response_1 = decode_message(
            service.handle_raw_message(encode_message(get_key_request))
        )
        self.assertEqual(get_key_response_1.status.code, StatusCode.OK)
        self.assertEqual(len(get_key_response_1.key_buffer), 48)

        get_key_response_2 = decode_message(
            service.handle_raw_message(encode_message(get_key_request))
        )
        self.assertEqual(get_key_response_2.status.code, StatusCode.OK)
        self.assertEqual(get_key_response_2.key_buffer, get_key_response_1.key_buffer)

        close_request = QKDCloseRequest(key_handle=key_handle)
        close_response = decode_message(
            service.handle_raw_message(encode_message(close_request))
        )
        self.assertEqual(close_response.status.code, StatusCode.OK)

        post_close_connect = decode_message(
            service.handle_raw_message(encode_message(connect_request))
        )
        self.assertEqual(post_close_connect.status.code, StatusCode.NOT_READY)
        self.assertFalse(post_close_connect.synchronized)

    def test_get_key_size_mismatch_for_same_key_handle(self) -> None:
        service = QKDProxyService()
        open_request = QKDOpenRequest(
            destination=Destination(ip="127.0.0.1", port=9000),
            qos=QoS(key_size_bytes=32),
        )
        open_response = decode_message(
            service.handle_raw_message(encode_message(open_request))
        )
        assert open_response.key_handle is not None
        key_handle = open_response.key_handle

        first_request = QKDGetKeyRequest(key_handle=key_handle, key_size_bytes=16)
        first_response = decode_message(
            service.handle_raw_message(encode_message(first_request))
        )
        self.assertEqual(first_response.status.code, StatusCode.OK)
        self.assertEqual(len(first_response.key_buffer), 16)

        second_request = QKDGetKeyRequest(key_handle=key_handle, key_size_bytes=32)
        second_response = decode_message(
            service.handle_raw_message(encode_message(second_request))
        )
        self.assertEqual(second_response.status.code, StatusCode.INVALID_ARGUMENT)
        self.assertEqual(second_response.key_buffer, b"")

    def test_connect_blocking_timeout(self) -> None:
        service = QKDProxyService()
        random_handle = os.urandom(64)
        request = QKDConnectBlockingRequest(key_handle=random_handle, timeout_ms=5)
        response = decode_message(service.handle_raw_message(encode_message(request)))
        self.assertEqual(response.status.code, StatusCode.TIMEOUT)
        self.assertFalse(response.synchronized)

    @patch("proxy.get_key", side_effect=RuntimeError("boom"))
    def test_get_key_failure_returns_error_response(self, _mock_get_key) -> None:
        service = QKDProxyService()
        open_request = QKDOpenRequest(
            destination=Destination(ip="127.0.0.1", port=9000),
            qos=QoS(key_size_bytes=32),
        )
        open_response = decode_message(
            service.handle_raw_message(encode_message(open_request))
        )
        assert open_response.key_handle is not None

        get_key_request = QKDGetKeyRequest(
            key_handle=open_response.key_handle,
            key_size_bytes=32,
        )
        get_key_response = decode_message(
            service.handle_raw_message(encode_message(get_key_request))
        )
        self.assertEqual(get_key_response.status.code, StatusCode.ERROR)
        self.assertEqual(get_key_response.key_buffer, b"")

    def test_response_instead_of_request_returns_error(self) -> None:
        service = QKDProxyService()
        bad_input = encode_message(QKDOpenResponse(status=Status(StatusCode.OK)))
        parsed = decode_message(service.handle_raw_message(bad_input))
        self.assertEqual(parsed.status.code, StatusCode.INVALID_ARGUMENT)

    def test_invalid_json_returns_fallback_error_payload(self) -> None:
        service = QKDProxyService()
        raw_response = service.handle_raw_message("{")
        data = json.loads(raw_response)
        self.assertEqual(data["payload"]["status"]["code"], StatusCode.INVALID_ARGUMENT)


if __name__ == "__main__":
    unittest.main()
