#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from qkd004_messages import (
    KEY_HANDLE_SIZE_BYTES,
    Destination,
    Operation,
    QoS,
    QKDCloseRequest,
    QKDCloseResponse,
    QKDConnectBlockingRequest,
    QKDConnectBlockingResponse,
    QKDConnectNonBlockRequest,
    QKDConnectNonBlockResponse,
    QKDGetKeyRequest,
    QKDGetKeyResponse,
    QKDOpenRequest,
    QKDOpenResponse,
    RequestType,
    ResponseType,
    Status,
    StatusCode,
    decode_message,
    encode_message,
)
from handler import get_key

LOGGER = logging.getLogger("qkd004.proxy")

PROTOBUF_STATUS_SUCCESS = 0
PROTOBUF_STATUS_NO_QKD_CONNECTION = 4
PROTOBUF_STATUS_TIMEOUT_ERROR = 6
PROTOBUF_STATUS_METADATA_BUFFER_TOO_SMALL = 8


def _pb_encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot encode negative values")
    chunks = bytearray()
    while True:
        to_write = value & 0x7F
        value >>= 7
        if value:
            chunks.append(to_write | 0x80)
        else:
            chunks.append(to_write)
            break
    return bytes(chunks)


def _pb_decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("protobuf varint too long")
    raise ValueError("truncated protobuf varint")


def _pb_encode_field_varint(field_number: int, value: int) -> bytes:
    key = (field_number << 3) | 0
    return _pb_encode_varint(key) + _pb_encode_varint(value)


def _pb_encode_field_bytes(field_number: int, value: bytes) -> bytes:
    key = (field_number << 3) | 2
    return _pb_encode_varint(key) + _pb_encode_varint(len(value)) + value


def _pb_parse_message(data: bytes) -> dict[int, list[tuple[str, int | bytes]]]:
    fields: dict[int, list[tuple[str, int | bytes]]] = {}
    offset = 0

    while offset < len(data):
        key, offset = _pb_decode_varint(data, offset)
        field_number = key >> 3
        wire_type = key & 0x07
        if field_number <= 0:
            raise ValueError("invalid protobuf field number")

        if wire_type == 0:
            value, offset = _pb_decode_varint(data, offset)
            parsed_value: tuple[str, int | bytes] = ("varint", value)
        elif wire_type == 2:
            size, offset = _pb_decode_varint(data, offset)
            end = offset + size
            if end > len(data):
                raise ValueError("truncated protobuf length-delimited field")
            parsed_value = ("bytes", data[offset:end])
            offset = end
        else:
            raise ValueError(f"unsupported protobuf wire type: {wire_type}")

        fields.setdefault(field_number, []).append(parsed_value)

    return fields


def _pb_first_varint(
    fields: dict[int, list[tuple[str, int | bytes]]],
    field_number: int,
    default: int = 0,
) -> int:
    for wire_type, value in fields.get(field_number, []):
        if wire_type == "varint":
            return int(value)
    return default


def _pb_first_bytes(
    fields: dict[int, list[tuple[str, int | bytes]]],
    field_number: int,
    default: bytes = b"",
) -> bytes:
    for wire_type, value in fields.get(field_number, []):
        if wire_type == "bytes":
            return bytes(value)
    return default


def _pb_first_string(
    fields: dict[int, list[tuple[str, int | bytes]]],
    field_number: int,
    default: str = "",
) -> str:
    raw = _pb_first_bytes(fields, field_number, b"")
    if not raw:
        return default
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return default


def _looks_like_json_stream(data: bytes) -> bool:
    probe = data.lstrip(b" \t\r\n")
    return probe.startswith(b"{") or probe.startswith(b"[")


def _hex_preview(data: bytes, max_bytes: int = 256) -> str:
    head = data[:max_bytes]
    text = head.hex()
    if len(data) > max_bytes:
        return f"{text}...(+{len(data) - max_bytes} bytes)"
    return text


def _ascii_preview(data: bytes, max_bytes: int = 256) -> str:
    head = data[:max_bytes]
    preview_chars: list[str] = []
    for byte in head:
        if 32 <= byte <= 126:
            preview_chars.append(chr(byte))
        else:
            preview_chars.append(".")
    preview = "".join(preview_chars)
    if len(data) > max_bytes:
        return f"{preview}...(+{len(data) - max_bytes} bytes)"
    return preview


def _summarize_pb_fields(
    fields: dict[int, list[tuple[str, int | bytes]]]
) -> dict[int, list[str]]:
    summary: dict[int, list[str]] = {}
    for field_number, values in fields.items():
        items: list[str] = []
        for wire_type, value in values:
            if wire_type == "varint":
                items.append(f"varint={int(value)}")
            else:
                assert isinstance(value, (bytes, bytearray))
                items.append(f"bytes[{len(value)}]")
        summary[field_number] = items
    return summary


@dataclass
class Association:
    key_handle: bytes
    destination: Destination
    qos: QoS
    created_at: float


class QKDProxyService:
    def __init__(self) -> None:
        self._associations: Dict[bytes, Association] = {}
        self._key_cache: Dict[bytes, bytes] = {}
        self._protobuf_stream_pairs: Dict[bytes, tuple[str, str]] = {}
        self._protobuf_key_cache: Dict[tuple[bytes, int, int], bytes] = {}
        self._lock = threading.Lock()

    def handle_raw_message(self, raw_message: str) -> str:
        try:
            data = json.loads(raw_message)
        except json.JSONDecodeError as exc:
            return self._encode_fallback_error(
                "INVALID",
                StatusCode.INVALID_ARGUMENT,
                f"invalid json: {exc.msg}",
            )

        try:
            operation = Operation(data.get("operation"))
        except Exception:
            return self._encode_fallback_error(
                str(data.get("operation", "UNKNOWN")),
                StatusCode.INVALID_ARGUMENT,
                "unknown operation",
            )

        try:
            message = decode_message(raw_message)
        except Exception as exc:
            error = self._build_error_response(
                operation,
                StatusCode.INVALID_ARGUMENT,
                f"invalid message: {exc}",
            )
            return encode_message(error)

        if not isinstance(
            message,
            (
                QKDOpenRequest,
                QKDConnectNonBlockRequest,
                QKDConnectBlockingRequest,
                QKDGetKeyRequest,
                QKDCloseRequest,
            ),
        ):
            error = self._build_error_response(
                operation,
                StatusCode.INVALID_ARGUMENT,
                "expected request message",
            )
            return encode_message(error)

        response = self._dispatch(message)
        return encode_message(response)

    def handle_raw_binary_message(self, raw_message: bytes) -> bytes:
        try:
            request = self._decode_protobuf_request(raw_message)
        except Exception as exc:
            return self._encode_protobuf_response(
                status=PROTOBUF_STATUS_METADATA_BUFFER_TOO_SMALL,
                detail=f"invalid protobuf payload: {exc}",
            )

        kind = request["kind"]
        if kind == "close":
            stream_id = request.get("stream_id", b"")
            if not stream_id:
                return self._encode_protobuf_response(
                    status=PROTOBUF_STATUS_NO_QKD_CONNECTION,
                    detail="missing stream id",
                )
            self._close_protobuf_stream(stream_id)
            return self._encode_protobuf_response(status=PROTOBUF_STATUS_SUCCESS)

        stream_id = request.get("stream_id", b"")
        source = request.get("source", "")
        destination = request.get("destination", "")
        if not stream_id and source and destination:
            stream_id = self._build_protobuf_stream_id(source, destination)
        if not stream_id:
            return self._encode_protobuf_response(
                status=PROTOBUF_STATUS_NO_QKD_CONNECTION,
                detail="cannot determine stream id",
            )

        index = int(request.get("index", 0))
        key_size = int(request.get("key_size", 32))
        if key_size <= 0:
            return self._encode_protobuf_response(
                status=PROTOBUF_STATUS_METADATA_BUFFER_TOO_SMALL,
                stream_id=stream_id,
                detail="invalid key size",
            )

        if source and destination:
            with self._lock:
                self._protobuf_stream_pairs[stream_id] = (source, destination)

        try:
            key_material = self._get_or_fetch_protobuf_key(stream_id, index, key_size)
        except TimeoutError as exc:
            return self._encode_protobuf_response(
                status=PROTOBUF_STATUS_TIMEOUT_ERROR,
                stream_id=stream_id,
                index=index,
                detail=str(exc),
            )
        except Exception as exc:
            LOGGER.exception(
                "Protobuf key retrieval failed stream_id=%s index=%d size=%d",
                stream_id.hex(),
                index,
                key_size,
            )
            return self._encode_protobuf_response(
                status=PROTOBUF_STATUS_NO_QKD_CONNECTION,
                stream_id=stream_id,
                index=index,
                detail=f"key retrieval failed: {exc}",
            )

        return self._encode_protobuf_response(
            status=PROTOBUF_STATUS_SUCCESS,
            stream_id=stream_id,
            index=index,
            key_material=key_material,
            source=source,
            destination=destination,
        )

    def _build_protobuf_stream_id(self, source: str, destination: str) -> bytes:
        first, second = sorted((source, destination))
        material = f"{first}|{second}".encode("utf-8")
        return hashlib.sha256(material).digest()[:16]

    def _close_protobuf_stream(self, stream_id: bytes) -> None:
        with self._lock:
            self._protobuf_stream_pairs.pop(stream_id, None)
            to_delete = [
                cache_key for cache_key in self._protobuf_key_cache if cache_key[0] == stream_id
            ]
            for cache_key in to_delete:
                self._protobuf_key_cache.pop(cache_key, None)

    def _get_or_fetch_protobuf_key(
        self, stream_id: bytes, index: int, key_size: int
    ) -> bytes:
        cache_key = (stream_id, index, key_size)
        with self._lock:
            cached = self._protobuf_key_cache.get(cache_key)
        if cached is not None:
            return cached

        key_material = get_key(key_size)
        with self._lock:
            existing = self._protobuf_key_cache.get(cache_key)
            if existing is not None:
                return existing
            self._protobuf_key_cache[cache_key] = key_material
        return key_material

    def _decode_protobuf_request(self, raw_message: bytes) -> dict[str, Any]:
        outer = _pb_parse_message(raw_message)
        embedded_fields: list[tuple[int, bytes]] = []
        for field_number, values in outer.items():
            for wire_type, value in values:
                if wire_type == "bytes":
                    embedded_fields.append((field_number, bytes(value)))

        if not embedded_fields:
            raise ValueError("no embedded protobuf message found")

        # Prefer field 1 because it is the one observed in wire capture.
        embedded_fields.sort(key=lambda entry: (entry[0] != 1, entry[0]))
        field_number, payload = embedded_fields[0]
        inner = _pb_parse_message(payload)

        if field_number == 3:
            stream_id = _pb_first_bytes(inner, 1, b"")
            return {"kind": "close", "stream_id": stream_id}

        if field_number == 2:
            stream_id = _pb_first_bytes(inner, 1, b"")
            index = _pb_first_varint(inner, 2, 0)
            key_size = _pb_first_varint(inner, 3, 32)
            return {
                "kind": "get",
                "stream_id": stream_id,
                "index": index,
                "key_size": key_size,
            }

        source = _pb_first_string(inner, 1, "")
        destination = _pb_first_string(inner, 2, "")
        first_varint = _pb_first_varint(inner, 3, 0)
        second_varint = _pb_first_varint(inner, 4, 0)
        stream_id = _pb_first_bytes(inner, 5, b"")

        key_size = second_varint if second_varint > 0 else first_varint
        if key_size <= 0:
            key_size = 32
        index = first_varint if second_varint > 0 else 0

        if not stream_id and source and destination:
            stream_id = self._build_protobuf_stream_id(source, destination)

        return {
            "kind": "open_get",
            "source": source,
            "destination": destination,
            "stream_id": stream_id,
            "index": index,
            "key_size": key_size,
        }

    def _encode_protobuf_response(
        self,
        status: int,
        stream_id: bytes = b"",
        index: int = 0,
        key_material: bytes = b"",
        source: str = "",
        destination: str = "",
        detail: str = "",
    ) -> bytes:
        # Field 1: open-like response payload (status, stream id, key, peer ids).
        open_payload = bytearray()
        open_payload.extend(_pb_encode_field_varint(1, status))
        if stream_id:
            open_payload.extend(_pb_encode_field_bytes(2, stream_id))
        open_payload.extend(_pb_encode_field_varint(3, index))
        if key_material:
            open_payload.extend(_pb_encode_field_bytes(4, key_material))
        if source:
            open_payload.extend(_pb_encode_field_bytes(6, source.encode("utf-8")))
        if destination:
            open_payload.extend(_pb_encode_field_bytes(7, destination.encode("utf-8")))
        if detail:
            open_payload.extend(_pb_encode_field_bytes(15, detail.encode("utf-8")))

        # Field 2: get-key-like response payload (status, index, key, stream id).
        get_payload = bytearray()
        get_payload.extend(_pb_encode_field_varint(1, status))
        get_payload.extend(_pb_encode_field_varint(2, index))
        if key_material:
            get_payload.extend(_pb_encode_field_bytes(3, key_material))
        if stream_id:
            get_payload.extend(_pb_encode_field_bytes(4, stream_id))
        if detail:
            get_payload.extend(_pb_encode_field_bytes(15, detail.encode("utf-8")))

        response = bytearray()
        response.extend(_pb_encode_field_bytes(1, bytes(open_payload)))
        response.extend(_pb_encode_field_bytes(2, bytes(get_payload)))
        response.extend(_pb_encode_field_varint(15, status))
        if stream_id:
            response.extend(_pb_encode_field_bytes(16, stream_id))
        if key_material:
            response.extend(_pb_encode_field_bytes(17, key_material))
        if detail:
            response.extend(_pb_encode_field_bytes(18, detail.encode("utf-8")))

        return bytes(response)

    def _dispatch(self, message: RequestType) -> ResponseType:
        if isinstance(message, QKDOpenRequest):
            return self._handle_open(message)
        if isinstance(message, QKDConnectNonBlockRequest):
            return self._handle_connect_nonblock(message)
        if isinstance(message, QKDConnectBlockingRequest):
            return self._handle_connect_blocking(message)
        if isinstance(message, QKDGetKeyRequest):
            return self._handle_get_key(message)
        if isinstance(message, QKDCloseRequest):
            return self._handle_close(message)
        return self._build_error_response(
            Operation.QKD_CLOSE,
            StatusCode.ERROR,
            f"unsupported request type: {type(message).__name__}",
        )

    def _handle_open(self, request: QKDOpenRequest) -> QKDOpenResponse:
        with self._lock:
            key_handle = request.key_handle
            if key_handle is None:
                key_handle = self._new_key_handle()
            elif key_handle in self._associations:
                return QKDOpenResponse(
                    status=Status(StatusCode.BUSY, "key_handle already in use")
                )

            self._associations[key_handle] = Association(
                key_handle=key_handle,
                destination=request.destination,
                qos=request.qos,
                created_at=time.monotonic(),
            )

        return QKDOpenResponse(status=Status(StatusCode.OK), key_handle=key_handle)

    def _handle_connect_nonblock(
        self, request: QKDConnectNonBlockRequest
    ) -> QKDConnectNonBlockResponse:
        if self._association_exists(request.key_handle):
            return QKDConnectNonBlockResponse(
                status=Status(StatusCode.OK), synchronized=True
            )
        return QKDConnectNonBlockResponse(
            status=Status(StatusCode.NOT_READY, "unknown key_handle"),
            synchronized=False,
        )

    def _handle_connect_blocking(
        self, request: QKDConnectBlockingRequest
    ) -> QKDConnectBlockingResponse:
        timeout_seconds = request.timeout_ms / 1000.0
        deadline = time.monotonic() + timeout_seconds

        while True:
            if self._association_exists(request.key_handle):
                return QKDConnectBlockingResponse(
                    status=Status(StatusCode.OK),
                    synchronized=True,
                )

            now = time.monotonic()
            if now >= deadline:
                return QKDConnectBlockingResponse(
                    status=Status(StatusCode.TIMEOUT, "rendezvous timeout"),
                    synchronized=False,
                )

            remaining = deadline - now
            time.sleep(min(0.05, remaining))

    def _handle_get_key(self, request: QKDGetKeyRequest) -> QKDGetKeyResponse:
        with self._lock:
            association = self._associations.get(request.key_handle)
            if association is None:
                return QKDGetKeyResponse(
                    status=Status(StatusCode.NOT_READY, "unknown key_handle"),
                    key_buffer=b"",
                )

            cached_key = self._key_cache.get(request.key_handle)
            if cached_key is None:
                try:
                    key_material = get_key(request.key_size_bytes)
                except Exception as exc:
                    LOGGER.exception("QKD_GET_KEY failed for handle %s", request.key_handle.hex())
                    return QKDGetKeyResponse(
                        status=Status(StatusCode.ERROR, f"key retrieval failed: {exc}"),
                        key_buffer=b"",
                    )
                self._key_cache[request.key_handle] = key_material
                return QKDGetKeyResponse(
                    status=Status(StatusCode.OK), key_buffer=key_material
                )

            if len(cached_key) != request.key_size_bytes:
                return QKDGetKeyResponse(
                    status=Status(
                        StatusCode.INVALID_ARGUMENT,
                        "key_size_bytes does not match cached key length for key_handle",
                    ),
                    key_buffer=b"",
                )

            return QKDGetKeyResponse(status=Status(StatusCode.OK), key_buffer=cached_key)

    def _handle_close(self, request: QKDCloseRequest) -> QKDCloseResponse:
        with self._lock:
            association = self._associations.pop(request.key_handle, None)
            self._key_cache.pop(request.key_handle, None)

        if association is None:
            return QKDCloseResponse(
                status=Status(StatusCode.NOT_READY, "unknown key_handle")
            )
        return QKDCloseResponse(status=Status(StatusCode.OK))

    def _association_exists(self, key_handle: bytes) -> bool:
        with self._lock:
            return key_handle in self._associations

    def _new_key_handle(self) -> bytes:
        while True:
            candidate = os.urandom(KEY_HANDLE_SIZE_BYTES)
            if candidate not in self._associations:
                return candidate

    def _build_error_response(
        self,
        operation: Operation,
        code: StatusCode,
        detail: str,
    ) -> ResponseType:
        status = Status(code=code, detail=detail)
        if operation == Operation.QKD_OPEN:
            return QKDOpenResponse(status=status)
        if operation == Operation.QKD_CONNECT_NONBLOCK:
            return QKDConnectNonBlockResponse(status=status, synchronized=False)
        if operation == Operation.QKD_CONNECT_BLOCKING:
            return QKDConnectBlockingResponse(status=status, synchronized=False)
        if operation == Operation.QKD_GET_KEY:
            return QKDGetKeyResponse(status=status, key_buffer=b"")
        return QKDCloseResponse(status=status)

    def _encode_fallback_error(
        self, operation: str, code: StatusCode, detail: str
    ) -> str:
        payload = {
            "direction": "response",
            "operation": operation,
            "payload": {"status": {"code": code.value, "detail": detail}},
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


class QKDProxyTCPHandler(socketserver.StreamRequestHandler):
    service: Optional[QKDProxyService] = None
    trace_wire: bool = False
    trace_limit: int = 256

    def _trace(self, message: str, *args: Any) -> None:
        if self.trace_wire:
            LOGGER.info("TRACE %s", message % args if args else message)

    def _trace_bytes(self, prefix: str, data: bytes) -> None:
        if not self.trace_wire:
            return
        LOGGER.info(
            "TRACE %s len=%d hex=%s ascii=%s",
            prefix,
            len(data),
            _hex_preview(data, self.trace_limit),
            _ascii_preview(data, self.trace_limit),
        )

    def handle(self) -> None:
        if self.service is None:
            raise RuntimeError("QKDProxyService is not configured")

        client = f"{self.client_address[0]}:{self.client_address[1]}"
        LOGGER.info("Connection from %s", client)

        mode: Optional[str] = None
        buffer = b""
        sock = self.connection
        sock.settimeout(0.5)

        try:
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    if mode == "binary" and buffer:
                        break
                    continue

                if not chunk:
                    break
                buffer += chunk
                self._trace_bytes("recv-chunk", chunk)

                if mode is None:
                    mode = "json" if _looks_like_json_stream(buffer) else "binary"
                    self._trace("detected-mode=%s", mode)
                    if mode == "json":
                        sock.settimeout(None)

                if mode == "json":
                    while b"\n" in buffer:
                        line_bytes, buffer = buffer.split(b"\n", 1)
                        if not line_bytes.strip():
                            continue

                        try:
                            raw_message = line_bytes.decode("utf-8").strip()
                        except UnicodeDecodeError:
                            raw_message = "{"

                        self._trace("json-request=%s", raw_message)
                        response = self.service.handle_raw_message(raw_message)
                        self._trace("json-response=%s", response)
                        try:
                            sock.sendall((response + "\n").encode("utf-8"))
                        except BrokenPipeError:
                            LOGGER.warning(
                                "Client %s closed connection before reading JSON response",
                                client,
                            )
                            return
        except ConnectionResetError:
            LOGGER.info("Connection reset by %s", client)
            return

        if mode == "json":
            if buffer.strip():
                try:
                    trailing_message = buffer.decode("utf-8").strip()
                except UnicodeDecodeError:
                    trailing_message = "{"
                self._trace("json-trailing-request=%s", trailing_message)
                response = self.service.handle_raw_message(trailing_message)
                self._trace("json-trailing-response=%s", response)
                try:
                    sock.sendall((response + "\n").encode("utf-8"))
                except BrokenPipeError:
                    LOGGER.warning(
                        "Client %s closed connection before reading trailing JSON response",
                        client,
                    )
            LOGGER.info("Connection closed for %s", client)
            return

        if buffer:
            self._trace_bytes("binary-request", buffer)
            try:
                parsed_request = self.service._decode_protobuf_request(buffer)  # noqa: SLF001
                self._trace("binary-request-parsed=%s", parsed_request)
            except Exception as exc:
                self._trace("binary-request-parse-error=%s", exc)

            response = self.service.handle_raw_binary_message(buffer)
            self._trace_bytes("binary-response", response)
            try:
                response_fields = _pb_parse_message(response)
                self._trace("binary-response-fields=%s", _summarize_pb_fields(response_fields))
            except Exception as exc:
                self._trace("binary-response-parse-error=%s", exc)
            try:
                sock.sendall(response)
            except BrokenPipeError:
                LOGGER.warning(
                    "Client %s closed connection before reading protobuf response",
                    client,
                )

        LOGGER.info("Connection closed for %s", client)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _resolve_path(config_path: Path, candidate: str) -> str:
    path = Path(candidate).expanduser()
    if not path.is_absolute():
        path = (config_path.parent / path).resolve()
    return str(path)


def _find_kme(kmes: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for kme in kmes:
        if str(kme.get("name", "")).strip() == name:
            return kme
    raise RuntimeError(f"kme '{name}' no existe en config")


def _discover_server_ca(config_path: Path) -> Optional[str]:
    search_dirs = [config_path.parent, config_path.parent / "certs"]
    matches: list[Path] = []

    for base in search_dirs:
        if not base.exists():
            continue
        matches.extend(base.glob("*server-ca*.crt"))

    # Keep deterministic order and de-duplicate.
    unique = sorted(set(match.resolve() for match in matches))
    if len(unique) == 1:
        return str(unique[0])
    return None


def _infer_sae_id_from_cert_entry(kme_config: dict[str, Any]) -> str:
    cert_candidate = (
        str(kme_config.get("crt", "")).strip()
        or str(kme_config.get("cert", "")).strip()
        or str(kme_config.get("pem", "")).strip()
    )
    if not cert_candidate:
        return ""
    return Path(cert_candidate).stem.strip()


def _configure_etsi014_from_config(
    config_file: str,
    local_kme_name: Optional[str],
    remote_kme_name: Optional[str],
) -> None:
    config_path = Path(config_file).expanduser().resolve()
    if not config_path.exists():
        raise RuntimeError(f"no existe el fichero de configuración: {config_path}")

    try:
        config_data = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"configuración JSON inválida en {config_path}: {exc.msg}"
        ) from exc

    kmes = config_data.get("kmes")
    if not isinstance(kmes, list) or not kmes:
        raise RuntimeError("configuración inválida: 'kmes' debe ser una lista no vacía")

    local_name = local_kme_name or str(kmes[0].get("name", "")).strip()
    if not local_name:
        raise RuntimeError("configuración inválida: falta 'name' en el KME local")
    local_kme = _find_kme(kmes, local_name)

    if remote_kme_name:
        remote_kme = _find_kme(kmes, remote_kme_name)
    elif len(kmes) >= 2:
        remote_kme = kmes[1] if kmes[0] is local_kme else kmes[0]
    else:
        remote_kme = local_kme

    host = str(local_kme.get("url", "")).strip()
    if not host:
        raise RuntimeError(f"configuración inválida: falta 'url' para kme '{local_name}'")

    remote_sae_id = (
        str(config_data.get("remote_sae_id", "")).strip()
        or str(config_data.get("remote-sae-id", "")).strip()
        or str(remote_kme.get("sae_id", "")).strip()
        or str(remote_kme.get("sae-id", "")).strip()
        or _infer_sae_id_from_cert_entry(remote_kme)
        or str(remote_kme.get("name", "")).strip()
    )
    if not remote_sae_id:
        raise RuntimeError(
            "configuración inválida: no se pudo determinar ETSI014_SAE_ID (usa 'sae_id' o 'name')"
        )

    cert_path = str(local_kme.get("crt", "")).strip() or str(local_kme.get("cert", "")).strip()
    key_path = str(local_kme.get("key", "")).strip()
    pem_path = str(local_kme.get("pem", "")).strip()
    if not cert_path:
        cert_path = pem_path

    if not cert_path:
        raise RuntimeError(
            f"configuración inválida: falta 'crt'/'cert'/'pem' para kme '{local_name}'"
        )

    ca_path = (
        str(local_kme.get("ca", "")).strip()
        or str(local_kme.get("ca_cert", "")).strip()
        or str(local_kme.get("ca-cert", "")).strip()
        or str(config_data.get("ca", "")).strip()
        or str(config_data.get("ca_cert", "")).strip()
        or str(config_data.get("ca-cert", "")).strip()
        or _discover_server_ca(config_path)
        or ""
    )

    os.environ["ETSI014_HOST"] = host
    os.environ["ETSI014_SAE_ID"] = remote_sae_id
    os.environ["ETSI014_CLIENT_CERT_FILE"] = _resolve_path(config_path, cert_path)
    if key_path:
        os.environ["ETSI014_CLIENT_KEY_FILE"] = _resolve_path(config_path, key_path)
    else:
        os.environ.pop("ETSI014_CLIENT_KEY_FILE", None)
    if ca_path:
        os.environ["ETSI014_CA_CERT_FILE"] = _resolve_path(config_path, ca_path)
    else:
        os.environ.pop("ETSI014_CA_CERT_FILE", None)

    if "ETSI014_ALLOW_RANDOM_FALLBACK" not in os.environ:
        os.environ["ETSI014_ALLOW_RANDOM_FALLBACK"] = str(
            bool(
                config_data.get(
                    "allow_random_fallback",
                    config_data.get("allow-random-fallback", False),
                )
            )
        ).lower()

    LOGGER.info(
        "ETSI014 configurado desde %s (local=%s, remoto=%s, host=%s, sae_id=%s)",
        config_path,
        local_name,
        str(remote_kme.get("name", "")).strip() or "<sin_nombre>",
        host,
        remote_sae_id,
    )


def run_server(host: str, port: int, trace_wire: bool = False, trace_limit: int = 256) -> None:
    service = QKDProxyService()

    class BoundHandler(QKDProxyTCPHandler):
        pass

    BoundHandler.service = service
    BoundHandler.trace_wire = trace_wire
    BoundHandler.trace_limit = trace_limit

    with ThreadedTCPServer((host, port), BoundHandler) as server:
        LOGGER.info("QKD004 proxy listening on %s:%d", host, port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            LOGGER.info("Shutting down proxy")
        finally:
            server.shutdown()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ETSI GS QKD 004 proxy (line-delimited JSON over TCP)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=7004, help="Bind port")
    parser.add_argument(
        "--config",
        default="config.json",
        help="Fichero JSON con configuración de KMEs para ETSI014",
    )
    parser.add_argument(
        "--local-kme",
        default=None,
        help="Nombre del KME local (campo 'name' en config.json). Por defecto: el primero.",
    )
    parser.add_argument(
        "--remote-kme",
        default=None,
        help="Nombre del KME remoto (campo 'name' en config.json). Por defecto: el otro KME.",
    )
    parser.add_argument(
        "--trace-wire",
        action="store_true",
        help="Traza payloads de red recibidos/enviados (JSON y binario) para depuración.",
    )
    parser.add_argument(
        "--trace-limit",
        type=int,
        default=256,
        help="Máximo de bytes a mostrar por payload en trazas.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    _configure_etsi014_from_config(
        config_file=args.config,
        local_kme_name=args.local_kme,
        remote_kme_name=args.remote_kme,
    )
    run_server(
        args.host,
        args.port,
        trace_wire=args.trace_wire,
        trace_limit=args.trace_limit,
    )


if __name__ == "__main__":
    main()
