#!/usr/bin/env python3
from __future__ import annotations

import argparse
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

HQS_INITIALIZE_OK = 0
HQS_INITIALIZE_ERROR_ALREADY_CLOSED = 1
HQS_INITIALIZE_ERROR_NOT_SUPPORTED_TIME_INTERVAL = 2
HQS_INITIALIZE_ERROR_NOT_SUPPORTED_KEY_LENGTH = 3
HQS_INITIALIZE_ERROR_WRONG_PARTNER_ID = 4
HQS_INITIALIZE_ERROR_PARTNER_QKD_NOT_AVAILABLE = 5

HQS_GET_STATUS_OK = 0
HQS_GET_STATUS_ERROR_FAILED_TO_GET_STATUS = 1

HQS_GET_KEY_OK = 0
HQS_GET_KEY_ERROR_SESSION_ID_NOT_ESTABLISHED = 1
HQS_GET_KEY_ERROR_KEY_NOT_READY = 2
HQS_GET_KEY_ERROR_WRONG_KEY_ID = 3

HQS_TERMINATE_OK = 0
HQS_TERMINATE_ERROR_SESSION_ID_NOT_FOUND = 1

HQS_GET_RANDOM_NUMBER_OK = 0
HQS_GET_RANDOM_NUMBER_ERROR_NOT_SUPPORTED_NUMBER_LENGTH = 1

DEFAULT_BINARY_IDLE_TIMEOUT_SECONDS = 0.15
MAX_RANDOM_NUMBER_BYTES = 65536


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


def _preview_handle(handle: bytes, chars: int = 12) -> str:
    if not handle:
        return "<empty>"
    return handle.hex()[:chars]


@dataclass
class Association:
    key_handle: bytes
    destination: Destination
    qos: QoS
    created_at: float


@dataclass
class HQSSession:
    session_id: int
    sitline_id: str
    sitline_partner_id: str
    key_interval_seconds: int
    key_length_bytes: int
    keys_by_id: Dict[int, bytes]
    created_at: float


class QKDProxyService:
    def __init__(self) -> None:
        self._associations: Dict[bytes, Association] = {}
        self._key_cache: Dict[bytes, bytes] = {}
        self._hqs_sessions: Dict[int, HQSSession] = {}
        self._next_hqs_session_id: int = 1
        self._lock = threading.Lock()

    def handle_raw_message(self, raw_message: str) -> str:
        LOGGER.debug("JSON request received bytes=%d", len(raw_message.encode("utf-8")))
        try:
            data = json.loads(raw_message)
        except json.JSONDecodeError as exc:
            LOGGER.warning("Invalid JSON request: %s", exc.msg)
            return self._encode_fallback_error(
                "INVALID",
                StatusCode.INVALID_ARGUMENT,
                f"invalid json: {exc.msg}",
            )

        try:
            operation = Operation(data.get("operation"))
        except Exception:
            LOGGER.warning("Unknown JSON operation=%r", data.get("operation"))
            return self._encode_fallback_error(
                str(data.get("operation", "UNKNOWN")),
                StatusCode.INVALID_ARGUMENT,
                "unknown operation",
            )

        try:
            message = decode_message(raw_message)
        except Exception as exc:
            LOGGER.warning("Failed to decode JSON message operation=%s error=%s", operation.value, exc)
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
            LOGGER.warning("JSON payload is not a request operation=%s", operation.value)
            error = self._build_error_response(
                operation,
                StatusCode.INVALID_ARGUMENT,
                "expected request message",
            )
            return encode_message(error)

        LOGGER.info("JSON operation=%s dispatch", operation.value)
        response = self._dispatch(message)
        response_status = getattr(response, "status", None)
        if response_status is not None:
            LOGGER.info(
                "JSON operation=%s completed status=%s",
                operation.value,
                getattr(response_status.code, "value", response_status.code),
            )
        return encode_message(response)

    def handle_raw_binary_message(self, raw_message: bytes) -> bytes:
        LOGGER.debug("HQS binary request received bytes=%d", len(raw_message))
        try:
            request = self._decode_protobuf_request(raw_message)
        except Exception as exc:
            LOGGER.warning("Invalid HQS protobuf payload: %s", exc)
            return self._encode_hqs_get_status_response(
                key_available=False,
                error=HQS_GET_STATUS_ERROR_FAILED_TO_GET_STATUS,
            )

        kind = request["kind"]
        LOGGER.info("HQS request kind=%s", kind)
        if kind == "initialize":
            return self._handle_hqs_initialize(
                sitline_id=str(request.get("sitline_id", "")),
                sitline_partner_id=str(request.get("sitline_partner_id", "")),
                key_interval_seconds=int(request.get("key_interval_seconds", 0)),
                key_length_bytes=int(request.get("key_length_bytes", 0)),
            )
        if kind == "get_status":
            return self._handle_hqs_get_status()
        if kind == "get_key":
            return self._handle_hqs_get_key(
                session_id=int(request.get("session_id", 0)),
                key_id=int(request.get("key_id", 0)),
            )
        if kind == "terminate":
            return self._handle_hqs_terminate(session_id=int(request.get("session_id", 0)))
        if kind == "get_random_number":
            return self._handle_hqs_get_random_number(length=int(request.get("length", 0)))

        LOGGER.warning("Unsupported HQS request kind=%s", kind)
        return self._encode_hqs_get_status_response(
            key_available=False,
            error=HQS_GET_STATUS_ERROR_FAILED_TO_GET_STATUS,
        )

    def _handle_hqs_initialize(
        self,
        sitline_id: str,
        sitline_partner_id: str,
        key_interval_seconds: int,
        key_length_bytes: int,
    ) -> bytes:
        LOGGER.info(
            "HQS Initialize request sitline_id=%s partner_id=%s key_interval_s=%d key_length_bytes=%d",
            sitline_id or "<empty>",
            sitline_partner_id or "<empty>",
            key_interval_seconds,
            key_length_bytes,
        )
        if not sitline_partner_id:
            LOGGER.warning("HQS Initialize rejected: missing sitline_partner_id")
            return self._encode_hqs_initialize_response(
                session_id=0,
                error=HQS_INITIALIZE_ERROR_WRONG_PARTNER_ID,
            )

        if key_interval_seconds <= 0:
            LOGGER.warning(
                "HQS Initialize rejected: invalid key_interval_s=%d",
                key_interval_seconds,
            )
            return self._encode_hqs_initialize_response(
                session_id=0,
                error=HQS_INITIALIZE_ERROR_NOT_SUPPORTED_TIME_INTERVAL,
            )

        if key_length_bytes <= 0:
            LOGGER.warning(
                "HQS Initialize rejected: invalid key_length_bytes=%d",
                key_length_bytes,
            )
            return self._encode_hqs_initialize_response(
                session_id=0,
                error=HQS_INITIALIZE_ERROR_NOT_SUPPORTED_KEY_LENGTH,
            )

        with self._lock:
            session_id = self._next_hqs_session_id
            while session_id in self._hqs_sessions:
                session_id += 1
                if session_id > 0x7FFFFFFF:
                    session_id = 1
                if session_id == self._next_hqs_session_id:
                    LOGGER.error("HQS Initialize failed: session id space exhausted")
                    return self._encode_hqs_initialize_response(
                        session_id=0,
                        error=HQS_INITIALIZE_ERROR_ALREADY_CLOSED,
                    )
            self._next_hqs_session_id = session_id + 1
            if self._next_hqs_session_id > 0x7FFFFFFF:
                self._next_hqs_session_id = 1
            self._hqs_sessions[session_id] = HQSSession(
                session_id=session_id,
                sitline_id=sitline_id,
                sitline_partner_id=sitline_partner_id,
                key_interval_seconds=key_interval_seconds,
                key_length_bytes=key_length_bytes,
                keys_by_id={},
                created_at=time.monotonic(),
            )
            active_sessions = len(self._hqs_sessions)

        LOGGER.info(
            "HQS Initialize success session_id=%d active_sessions=%d",
            session_id,
            active_sessions,
        )
        return self._encode_hqs_initialize_response(
            session_id=session_id,
            error=HQS_INITIALIZE_OK,
        )

    def _handle_hqs_get_status(self) -> bytes:
        with self._lock:
            key_available = bool(self._hqs_sessions)
            active_sessions = len(self._hqs_sessions)
        LOGGER.info(
            "HQS GetStatus key_available=%s active_sessions=%d",
            key_available,
            active_sessions,
        )
        return self._encode_hqs_get_status_response(
            key_available=key_available,
            error=HQS_GET_STATUS_OK,
        )

    def _handle_hqs_get_key(self, session_id: int, key_id: int) -> bytes:
        LOGGER.info("HQS GetKey request session_id=%d key_id=%d", session_id, key_id)
        if session_id <= 0 or key_id < 0:
            LOGGER.warning(
                "HQS GetKey rejected: invalid session/key values session_id=%d key_id=%d",
                session_id,
                key_id,
            )
            return self._encode_hqs_get_key_response(
                session_id=session_id,
                key_id=key_id,
                key_data=b"",
                key_length=0,
                error=HQS_GET_KEY_ERROR_WRONG_KEY_ID,
            )

        with self._lock:
            session = self._hqs_sessions.get(session_id)
            if session is None:
                LOGGER.warning("HQS GetKey rejected: session not found session_id=%d", session_id)
                return self._encode_hqs_get_key_response(
                    session_id=session_id,
                    key_id=key_id,
                    key_data=b"",
                    key_length=0,
                    error=HQS_GET_KEY_ERROR_SESSION_ID_NOT_ESTABLISHED,
                )
            cached_key = session.keys_by_id.get(key_id)
            key_length_bytes = session.key_length_bytes
            active_sessions = len(self._hqs_sessions)
        cache_hit = cached_key is not None
        LOGGER.debug(
            "HQS GetKey lookup session_id=%d key_id=%d cache_hit=%s key_length_bytes=%d active_sessions=%d",
            session_id,
            key_id,
            cache_hit,
            key_length_bytes,
            active_sessions,
        )

        if cached_key is None:
            try:
                key_material = get_key(key_length_bytes)
            except Exception as exc:
                LOGGER.exception(
                    "HQS GetKey failed session_id=%d key_id=%d", session_id, key_id
                )
                return self._encode_hqs_get_key_response(
                    session_id=session_id,
                    key_id=key_id,
                    key_data=b"",
                    key_length=0,
                    error=HQS_GET_KEY_ERROR_KEY_NOT_READY,
                )

            if len(key_material) != key_length_bytes:
                LOGGER.error(
                    "HQS GetKey length mismatch session_id=%d key_id=%d expected=%d got=%d",
                    session_id,
                    key_id,
                    key_length_bytes,
                    len(key_material),
                )
                return self._encode_hqs_get_key_response(
                    session_id=session_id,
                    key_id=key_id,
                    key_data=b"",
                    key_length=0,
                    error=HQS_GET_KEY_ERROR_KEY_NOT_READY,
                )

            with self._lock:
                current_session = self._hqs_sessions.get(session_id)
                if current_session is None:
                    return self._encode_hqs_get_key_response(
                        session_id=session_id,
                        key_id=key_id,
                        key_data=b"",
                        key_length=0,
                        error=HQS_GET_KEY_ERROR_SESSION_ID_NOT_ESTABLISHED,
                    )
                cached_key = current_session.keys_by_id.setdefault(key_id, key_material)
                cache_hit = cached_key is not key_material

        LOGGER.info(
            "HQS GetKey success session_id=%d key_id=%d key_length=%d cache_hit=%s",
            session_id,
            key_id,
            len(cached_key),
            cache_hit,
        )

        return self._encode_hqs_get_key_response(
            session_id=session_id,
            key_id=key_id,
            key_data=cached_key,
            key_length=len(cached_key),
            error=HQS_GET_KEY_OK,
        )

    def _handle_hqs_terminate(self, session_id: int) -> bytes:
        LOGGER.info("HQS Terminate request session_id=%d", session_id)
        if session_id <= 0:
            LOGGER.warning("HQS Terminate rejected: invalid session_id=%d", session_id)
            return self._encode_hqs_terminate_response(
                session_id=session_id,
                error=HQS_TERMINATE_ERROR_SESSION_ID_NOT_FOUND,
            )

        with self._lock:
            removed = self._hqs_sessions.pop(session_id, None)
            active_sessions = len(self._hqs_sessions)

        LOGGER.info(
            "HQS Terminate result session_id=%d removed=%s active_sessions=%d",
            session_id,
            removed is not None,
            active_sessions,
        )
        return self._encode_hqs_terminate_response(
            session_id=session_id,
            error=HQS_TERMINATE_OK
            if removed is not None
            else HQS_TERMINATE_ERROR_SESSION_ID_NOT_FOUND,
        )

    def _handle_hqs_get_random_number(self, length: int) -> bytes:
        LOGGER.info("HQS GetRandomNumber request length=%d", length)
        if length <= 0 or length > MAX_RANDOM_NUMBER_BYTES:
            LOGGER.warning(
                "HQS GetRandomNumber rejected: unsupported length=%d max=%d",
                length,
                MAX_RANDOM_NUMBER_BYTES,
            )
            return self._encode_hqs_get_random_number_response(
                random_number=b"",
                length=0,
                error=HQS_GET_RANDOM_NUMBER_ERROR_NOT_SUPPORTED_NUMBER_LENGTH,
            )

        random_data = os.urandom(length)
        LOGGER.info("HQS GetRandomNumber success length=%d", length)
        return self._encode_hqs_get_random_number_response(
            random_number=random_data,
            length=length,
            error=HQS_GET_RANDOM_NUMBER_OK,
        )

    def _decode_protobuf_request(self, raw_message: bytes) -> dict[str, Any]:
        outer = _pb_parse_message(raw_message)
        LOGGER.debug("HQS protobuf outer fields=%s", _summarize_pb_fields(outer))
        embedded_fields: list[tuple[int, bytes]] = []
        for field_number, values in outer.items():
            for wire_type, value in values:
                if wire_type == "bytes":
                    embedded_fields.append((field_number, bytes(value)))

        if not embedded_fields:
            raise ValueError("no embedded protobuf message found")

        request_fields = [entry for entry in embedded_fields if 1 <= entry[0] <= 5]
        if len(request_fields) != 1:
            raise ValueError("expected exactly one HQS Request.msg field")

        field_number, payload = request_fields[0]
        inner = _pb_parse_message(payload)
        LOGGER.debug(
            "HQS protobuf request decoded msg_field=%d inner_fields=%s",
            field_number,
            _summarize_pb_fields(inner),
        )

        if field_number == 1:
            return {
                "kind": "initialize",
                "sitline_id": _pb_first_string(inner, 1, ""),
                "sitline_partner_id": _pb_first_string(inner, 2, ""),
                "key_interval_seconds": _pb_first_varint(inner, 3, 0),
                "key_length_bytes": _pb_first_varint(inner, 4, 0),
            }
        if field_number == 2:
            return {"kind": "get_status"}
        if field_number == 3:
            return {
                "kind": "get_key",
                "session_id": _pb_first_varint(inner, 1, 0),
                "key_id": _pb_first_varint(inner, 2, 0),
            }
        if field_number == 4:
            return {
                "kind": "terminate",
                "session_id": _pb_first_varint(inner, 1, 0),
            }
        if field_number == 5:
            return {
                "kind": "get_random_number",
                "length": _pb_first_varint(inner, 1, 0),
            }

        raise ValueError(f"unsupported HQS request field number: {field_number}")

    def _encode_hqs_initialize_response(self, session_id: int, error: int) -> bytes:
        payload = bytearray()
        payload.extend(_pb_encode_field_varint(1, session_id))
        payload.extend(_pb_encode_field_varint(2, error))
        return _pb_encode_field_bytes(1, bytes(payload))

    def _encode_hqs_get_status_response(self, key_available: bool, error: int) -> bytes:
        payload = bytearray()
        payload.extend(_pb_encode_field_varint(1, 1 if key_available else 0))
        payload.extend(_pb_encode_field_varint(2, error))
        return _pb_encode_field_bytes(2, bytes(payload))

    def _encode_hqs_get_key_response(
        self,
        session_id: int,
        key_id: int,
        key_data: bytes,
        key_length: int,
        error: int,
    ) -> bytes:
        payload = bytearray()
        payload.extend(_pb_encode_field_varint(1, session_id))
        payload.extend(_pb_encode_field_varint(2, key_id))
        if key_data:
            payload.extend(_pb_encode_field_bytes(3, key_data))
        payload.extend(_pb_encode_field_varint(4, key_length))
        payload.extend(_pb_encode_field_varint(5, error))
        return _pb_encode_field_bytes(3, bytes(payload))

    def _encode_hqs_terminate_response(self, session_id: int, error: int) -> bytes:
        payload = bytearray()
        payload.extend(_pb_encode_field_varint(1, session_id))
        payload.extend(_pb_encode_field_varint(2, error))
        return _pb_encode_field_bytes(4, bytes(payload))

    def _encode_hqs_get_random_number_response(
        self,
        random_number: bytes,
        length: int,
        error: int,
    ) -> bytes:
        payload = bytearray()
        if random_number:
            payload.extend(_pb_encode_field_bytes(1, random_number))
        payload.extend(_pb_encode_field_varint(2, length))
        payload.extend(_pb_encode_field_varint(3, error))
        return _pb_encode_field_bytes(5, bytes(payload))

    def _dispatch(self, message: RequestType) -> ResponseType:
        LOGGER.debug("Dispatch JSON request type=%s", type(message).__name__)
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
        LOGGER.info(
            "QKD_OPEN request destination=%s:%d key_size=%d timeout_ms=%d",
            request.destination.ip,
            request.destination.port,
            request.qos.key_size_bytes,
            request.qos.timeout_ms,
        )
        with self._lock:
            key_handle = request.key_handle
            if key_handle is None:
                key_handle = self._new_key_handle()
            elif key_handle in self._associations:
                LOGGER.warning(
                    "QKD_OPEN rejected: key_handle already in use handle=%s",
                    _preview_handle(key_handle),
                )
                return QKDOpenResponse(
                    status=Status(StatusCode.BUSY, "key_handle already in use")
                )

            self._associations[key_handle] = Association(
                key_handle=key_handle,
                destination=request.destination,
                qos=request.qos,
                created_at=time.monotonic(),
            )
            associations_total = len(self._associations)

        LOGGER.info(
            "QKD_OPEN success handle=%s associations_total=%d",
            _preview_handle(key_handle),
            associations_total,
        )
        return QKDOpenResponse(status=Status(StatusCode.OK), key_handle=key_handle)

    def _handle_connect_nonblock(
        self, request: QKDConnectNonBlockRequest
    ) -> QKDConnectNonBlockResponse:
        LOGGER.info(
            "QKD_CONNECT_NONBLOCK request handle=%s",
            _preview_handle(request.key_handle),
        )
        if self._association_exists(request.key_handle):
            LOGGER.info("QKD_CONNECT_NONBLOCK success handle=%s", _preview_handle(request.key_handle))
            return QKDConnectNonBlockResponse(
                status=Status(StatusCode.OK), synchronized=True
            )
        LOGGER.warning(
            "QKD_CONNECT_NONBLOCK not_ready unknown handle=%s",
            _preview_handle(request.key_handle),
        )
        return QKDConnectNonBlockResponse(
            status=Status(StatusCode.NOT_READY, "unknown key_handle"),
            synchronized=False,
        )

    def _handle_connect_blocking(
        self, request: QKDConnectBlockingRequest
    ) -> QKDConnectBlockingResponse:
        LOGGER.info(
            "QKD_CONNECT_BLOCKING request handle=%s timeout_ms=%d",
            _preview_handle(request.key_handle),
            request.timeout_ms,
        )
        timeout_seconds = request.timeout_ms / 1000.0
        deadline = time.monotonic() + timeout_seconds

        while True:
            if self._association_exists(request.key_handle):
                LOGGER.info(
                    "QKD_CONNECT_BLOCKING synchronized handle=%s",
                    _preview_handle(request.key_handle),
                )
                return QKDConnectBlockingResponse(
                    status=Status(StatusCode.OK),
                    synchronized=True,
                )

            now = time.monotonic()
            if now >= deadline:
                LOGGER.warning(
                    "QKD_CONNECT_BLOCKING timeout handle=%s timeout_ms=%d",
                    _preview_handle(request.key_handle),
                    request.timeout_ms,
                )
                return QKDConnectBlockingResponse(
                    status=Status(StatusCode.TIMEOUT, "rendezvous timeout"),
                    synchronized=False,
                )

            remaining = deadline - now
            time.sleep(min(0.05, remaining))

    def _handle_get_key(self, request: QKDGetKeyRequest) -> QKDGetKeyResponse:
        LOGGER.info(
            "QKD_GET_KEY request handle=%s key_size_bytes=%d",
            _preview_handle(request.key_handle),
            request.key_size_bytes,
        )
        with self._lock:
            association = self._associations.get(request.key_handle)
            if association is None:
                LOGGER.warning(
                    "QKD_GET_KEY not_ready unknown handle=%s",
                    _preview_handle(request.key_handle),
                )
                return QKDGetKeyResponse(
                    status=Status(StatusCode.NOT_READY, "unknown key_handle"),
                    key_buffer=b"",
                )

            cached_key = self._key_cache.get(request.key_handle)
            cache_hit = cached_key is not None
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
                LOGGER.info(
                    "QKD_GET_KEY success handle=%s key_length=%d cache_hit=false",
                    _preview_handle(request.key_handle),
                    len(key_material),
                )
                return QKDGetKeyResponse(
                    status=Status(StatusCode.OK), key_buffer=key_material
                )

            if len(cached_key) != request.key_size_bytes:
                LOGGER.warning(
                    "QKD_GET_KEY invalid_argument handle=%s expected_size=%d cached_size=%d",
                    _preview_handle(request.key_handle),
                    request.key_size_bytes,
                    len(cached_key),
                )
                return QKDGetKeyResponse(
                    status=Status(
                        StatusCode.INVALID_ARGUMENT,
                        "key_size_bytes does not match cached key length for key_handle",
                    ),
                    key_buffer=b"",
                )

            LOGGER.info(
                "QKD_GET_KEY success handle=%s key_length=%d cache_hit=%s",
                _preview_handle(request.key_handle),
                len(cached_key),
                cache_hit,
            )
            return QKDGetKeyResponse(status=Status(StatusCode.OK), key_buffer=cached_key)

    def _handle_close(self, request: QKDCloseRequest) -> QKDCloseResponse:
        LOGGER.info("QKD_CLOSE request handle=%s", _preview_handle(request.key_handle))
        with self._lock:
            association = self._associations.pop(request.key_handle, None)
            self._key_cache.pop(request.key_handle, None)
            associations_total = len(self._associations)

        if association is None:
            LOGGER.warning("QKD_CLOSE not_ready unknown handle=%s", _preview_handle(request.key_handle))
            return QKDCloseResponse(
                status=Status(StatusCode.NOT_READY, "unknown key_handle")
            )
        LOGGER.info(
            "QKD_CLOSE success handle=%s associations_total=%d",
            _preview_handle(request.key_handle),
            associations_total,
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
        LOGGER.warning(
            "Building error response operation=%s code=%s detail=%s",
            operation.value,
            code.value,
            detail,
        )
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
        LOGGER.warning(
            "Fallback JSON error operation=%s code=%s detail=%s",
            operation,
            code.value,
            detail,
        )
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

    def _serve_binary_buffer(self, sock: socket.socket, client: str, payload: bytes) -> bool:
        self._trace_bytes("binary-request", payload)
        parsed_request: Optional[dict[str, Any]] = None
        try:
            parsed_request = self.service._decode_protobuf_request(payload)  # noqa: SLF001
            self._trace("binary-request-parsed=%s", parsed_request)
        except Exception as exc:
            self._trace("binary-request-parse-error=%s", exc)
            LOGGER.warning(
                "HQS TCP request parse error client=%s bytes=%d error=%s",
                client,
                len(payload),
                exc,
            )

        if parsed_request is not None:
            LOGGER.info(
                "HQS TCP request client=%s kind=%s bytes=%d",
                client,
                parsed_request.get("kind", "<unknown>"),
                len(payload),
            )

        response = self.service.handle_raw_binary_message(payload)
        self._trace_bytes("binary-response", response)
        try:
            response_fields = _pb_parse_message(response)
            self._trace("binary-response-fields=%s", _summarize_pb_fields(response_fields))
        except Exception as exc:
            self._trace("binary-response-parse-error=%s", exc)

        try:
            sock.sendall(response)
            LOGGER.info("HQS TCP response client=%s bytes=%d", client, len(response))
            return True
        except BrokenPipeError:
            LOGGER.warning(
                "Client %s closed connection before reading protobuf response",
                client,
            )
            return False

    def handle(self) -> None:
        if self.service is None:
            raise RuntimeError("QKDProxyService is not configured")

        client = f"{self.client_address[0]}:{self.client_address[1]}"
        LOGGER.info("Connection from %s", client)

        mode: Optional[str] = None
        buffer = b""
        sock = self.connection
        sock.settimeout(DEFAULT_BINARY_IDLE_TIMEOUT_SECONDS)

        try:
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    if mode == "binary" and buffer:
                        if not self._serve_binary_buffer(sock, client, buffer):
                            return
                        buffer = b""
                    continue

                if not chunk:
                    if mode == "binary" and buffer:
                        self._serve_binary_buffer(sock, client, buffer)
                    break
                buffer += chunk
                self._trace_bytes("recv-chunk", chunk)

                if mode is None:
                    mode = "json" if _looks_like_json_stream(buffer) else "binary"
                    self._trace("detected-mode=%s", mode)
                    LOGGER.info("Connection %s detected mode=%s", client, mode)
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
                        LOGGER.info("JSON TCP request client=%s bytes=%d", client, len(line_bytes))
                        response = self.service.handle_raw_message(raw_message)
                        self._trace("json-response=%s", response)
                        try:
                            sock.sendall((response + "\n").encode("utf-8"))
                            LOGGER.info("JSON TCP response client=%s bytes=%d", client, len(response))
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
                LOGGER.info("JSON TCP trailing request client=%s bytes=%d", client, len(buffer))
                response = self.service.handle_raw_message(trailing_message)
                self._trace("json-trailing-response=%s", response)
                try:
                    sock.sendall((response + "\n").encode("utf-8"))
                    LOGGER.info("JSON TCP trailing response client=%s bytes=%d", client, len(response))
                except BrokenPipeError:
                    LOGGER.warning(
                        "Client %s closed connection before reading trailing JSON response",
                        client,
                    )
            LOGGER.info("Connection closed for %s", client)
            return

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
    LOGGER.info("Loading proxy config file=%s", config_path)
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
    LOGGER.debug("Loaded %d KME entries from config", len(kmes))

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

    LOGGER.debug(
        "ETSI014 paths cert=%s key=%s ca=%s allow_random_fallback=%s",
        os.environ.get("ETSI014_CLIENT_CERT_FILE", "<unset>"),
        os.environ.get("ETSI014_CLIENT_KEY_FILE", "<unset>"),
        os.environ.get("ETSI014_CA_CERT_FILE", "<unset>"),
        os.environ.get("ETSI014_ALLOW_RANDOM_FALLBACK", "<unset>"),
    )
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
    LOGGER.info(
        "Proxy runtime options host=%s port=%d trace_wire=%s trace_limit=%d",
        host,
        port,
        trace_wire,
        trace_limit,
    )

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
        description="ETSI GS QKD 004 proxy (JSON y HQS protobuf sobre TCP)"
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=5000, help="Bind port")
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
