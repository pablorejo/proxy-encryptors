#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import socket
import sys
from typing import Any, Tuple

from qkd004_messages import (
    KEY_HANDLE_SIZE_BYTES,
    Destination,
    QoS,
    QKDCloseRequest,
    QKDConnectBlockingRequest,
    QKDConnectNonBlockRequest,
    QKDGetKeyRequest,
    QKDOpenRequest,
    StatusCode,
    decode_message,
    encode_message,
)


def send_request(stream: Any, message: Any) -> Tuple[str, Any]:
    raw_request = encode_message(message)
    stream.write((raw_request + "\n").encode("utf-8"))
    stream.flush()

    raw_response = stream.readline().decode("utf-8").strip()
    if not raw_response:
        raise RuntimeError("proxy closed connection without response")

    return raw_response, decode_message(raw_response)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cliente ETSI GS QKD 004 (line-delimited JSON over TCP)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host del proxy ETSI004")
    parser.add_argument("--port", type=int, default=7004, help="Puerto del proxy ETSI004")
    parser.add_argument("--dest-ip", default="127.0.0.1", help="Destino para QKD_OPEN")
    parser.add_argument("--dest-port", type=int, default=9000, help="Puerto destino para QKD_OPEN")
    parser.add_argument("--key-size", type=int, default=32, help="Tamaño de clave en bytes")
    parser.add_argument("--min-bitrate", type=int, default=1000, help="QoS min_bitrate_bps")
    parser.add_argument("--timeout-ms", type=int, default=1000, help="Timeout para QoS/connect blocking")
    parser.add_argument(
        "--connect-mode",
        choices=("none", "nonblock", "blocking"),
        default="nonblock",
        help="Tipo de conexión tras QKD_OPEN",
    )
    parser.add_argument(
        "--key-format",
        choices=("hex", "base64"),
        default="hex",
        help="Formato de salida de key_buffer",
    )
    parser.add_argument(
        "--show-raw",
        action="store_true",
        help="Muestra JSON raw request/response",
    )
    parser.add_argument(
        "--reuse-key-handle-b64",
        default=None,
        help="Reutiliza este key_handle (base64) y omite QKD_OPEN",
    )
    parser.add_argument(
        "--no-close",
        action="store_true",
        help="No envía QKD_CLOSE al final (útil para reutilizar key_handle)",
    )
    args = parser.parse_args()

    try:
        with socket.create_connection((args.host, args.port), timeout=5) as sock:
            stream = sock.makefile("rwb")

            if args.reuse_key_handle_b64:
                try:
                    key_handle = base64.b64decode(
                        args.reuse_key_handle_b64.encode("ascii"), validate=True
                    )
                except (binascii.Error, UnicodeEncodeError) as exc:
                    raise RuntimeError(
                        f"--reuse-key-handle-b64 inválido: {exc}"
                    ) from exc

                if len(key_handle) != KEY_HANDLE_SIZE_BYTES:
                    raise RuntimeError(
                        f"--reuse-key-handle-b64 inválido: "
                        f"debe decodificar a {KEY_HANDLE_SIZE_BYTES} bytes, "
                        f"pero son {len(key_handle)}"
                    )
                print("QKD_OPEN: SKIPPED (reuse existing key_handle)")
            else:
                open_request = QKDOpenRequest(
                    destination=Destination(ip=args.dest_ip, port=args.dest_port),
                    qos=QoS(
                        key_size_bytes=args.key_size,
                        min_bitrate_bps=args.min_bitrate,
                        timeout_ms=args.timeout_ms,
                    ),
                )
                if args.show_raw:
                    print(">>", encode_message(open_request))
                raw_open, open_response = send_request(stream, open_request)
                if args.show_raw:
                    print("<<", raw_open)

                print(f"QKD_OPEN: {open_response.status.code}")
                if open_response.status.code != StatusCode.OK or open_response.key_handle is None:
                    return 1
                key_handle = open_response.key_handle

            key_handle_b64 = base64.b64encode(key_handle).decode("ascii")
            print(f"key_handle_b64={key_handle_b64}")

            if args.connect_mode == "nonblock":
                connect_request = QKDConnectNonBlockRequest(key_handle=key_handle)
                if args.show_raw:
                    print(">>", encode_message(connect_request))
                raw_connect, connect_response = send_request(stream, connect_request)
                if args.show_raw:
                    print("<<", raw_connect)
                print(
                    f"QKD_CONNECT_NONBLOCK: {connect_response.status.code}"
                    f" synchronized={connect_response.synchronized}"
                )
                if connect_response.status.code != StatusCode.OK:
                    return 1
            elif args.connect_mode == "blocking":
                connect_request = QKDConnectBlockingRequest(
                    key_handle=key_handle, timeout_ms=args.timeout_ms
                )
                if args.show_raw:
                    print(">>", encode_message(connect_request))
                raw_connect, connect_response = send_request(stream, connect_request)
                if args.show_raw:
                    print("<<", raw_connect)
                print(
                    f"QKD_CONNECT_BLOCKING: {connect_response.status.code}"
                    f" synchronized={connect_response.synchronized}"
                )
                if connect_response.status.code != StatusCode.OK:
                    return 1

            get_key_request = QKDGetKeyRequest(key_handle=key_handle, key_size_bytes=args.key_size)
            if args.show_raw:
                print(">>", encode_message(get_key_request))
            raw_get_key, get_key_response = send_request(stream, get_key_request)
            if args.show_raw:
                print("<<", raw_get_key)

            print(f"QKD_GET_KEY: {get_key_response.status.code}")
            if get_key_response.status.code != StatusCode.OK:
                return 1

            if args.key_format == "base64":
                key_text = base64.b64encode(get_key_response.key_buffer).decode("ascii")
            else:
                key_text = get_key_response.key_buffer.hex()
            print(f"key_size={len(get_key_response.key_buffer)} bytes")
            print(f"key_{args.key_format}={key_text}")

            if args.no_close:
                print("QKD_CLOSE: SKIPPED (--no-close)")
                return 0

            close_request = QKDCloseRequest(key_handle=key_handle)
            if args.show_raw:
                print(">>", encode_message(close_request))
            raw_close, close_response = send_request(stream, close_request)
            if args.show_raw:
                print("<<", raw_close)

            print(f"QKD_CLOSE: {close_response.status.code}")
            return 0 if close_response.status.code == StatusCode.OK else 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
