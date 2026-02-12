from __future__ import annotations

import base64
import ipaddress
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Type, Union

KEY_HANDLE_SIZE_BYTES = 64


class Operation(str, Enum):
    QKD_OPEN = "QKD_OPEN"
    QKD_CONNECT_NONBLOCK = "QKD_CONNECT_NONBLOCK"
    QKD_CONNECT_BLOCKING = "QKD_CONNECT_BLOCKING"
    QKD_GET_KEY = "QKD_GET_KEY"
    QKD_CLOSE = "QKD_CLOSE"


class StatusCode(str, Enum):
    OK = "OK"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    BUSY = "BUSY"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    NOT_READY = "NOT_READY"


def _validate_key_handle(key_handle: bytes) -> None:
    if len(key_handle) != KEY_HANDLE_SIZE_BYTES:
        raise ValueError(
            f"key_handle must be {KEY_HANDLE_SIZE_BYTES} bytes, got {len(key_handle)}"
        )


def _bytes_to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_to_bytes(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


@dataclass(frozen=True)
class Destination:
    ip: str
    port: int

    def __post_init__(self) -> None:
        ipaddress.ip_address(self.ip)
        if not (1 <= self.port <= 65535):
            raise ValueError("port must be between 1 and 65535")

    def to_dict(self) -> Dict[str, Any]:
        return {"ip": self.ip, "port": self.port}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Destination":
        return cls(ip=data["ip"], port=data["port"])


@dataclass(frozen=True)
class QoS:
    key_size_bytes: int
    min_bitrate_bps: int = 0
    timeout_ms: int = 0
    blocking_get: bool = True

    def __post_init__(self) -> None:
        if self.key_size_bytes <= 0:
            raise ValueError("key_size_bytes must be > 0")
        if self.min_bitrate_bps < 0:
            raise ValueError("min_bitrate_bps must be >= 0")
        if self.timeout_ms < 0:
            raise ValueError("timeout_ms must be >= 0")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_size_bytes": self.key_size_bytes,
            "min_bitrate_bps": self.min_bitrate_bps,
            "timeout_ms": self.timeout_ms,
            "blocking_get": self.blocking_get,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QoS":
        return cls(
            key_size_bytes=data["key_size_bytes"],
            min_bitrate_bps=data.get("min_bitrate_bps", 0),
            timeout_ms=data.get("timeout_ms", 0),
            blocking_get=data.get("blocking_get", True),
        )


@dataclass(frozen=True)
class Status:
    code: StatusCode
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code.value, "detail": self.detail}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Status":
        return cls(code=StatusCode(data["code"]), detail=data.get("detail", ""))


@dataclass(frozen=True)
class QKDOpenRequest:
    destination: Destination
    qos: QoS
    key_handle: Optional[bytes] = None

    def __post_init__(self) -> None:
        if self.key_handle is not None:
            _validate_key_handle(self.key_handle)

    def to_wire_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "destination": self.destination.to_dict(),
            "qos": self.qos.to_dict(),
        }
        if self.key_handle is not None:
            payload["key_handle_b64"] = _bytes_to_b64(self.key_handle)
        return {
            "direction": "request",
            "operation": Operation.QKD_OPEN.value,
            "payload": payload,
        }

    @classmethod
    def from_wire_dict(cls, data: Dict[str, Any]) -> "QKDOpenRequest":
        payload = data["payload"]
        key_handle = (
            _b64_to_bytes(payload["key_handle_b64"])
            if "key_handle_b64" in payload
            else None
        )
        return cls(
            destination=Destination.from_dict(payload["destination"]),
            qos=QoS.from_dict(payload["qos"]),
            key_handle=key_handle,
        )


@dataclass(frozen=True)
class QKDOpenResponse:
    status: Status
    key_handle: Optional[bytes] = None

    def __post_init__(self) -> None:
        if self.key_handle is not None:
            _validate_key_handle(self.key_handle)

    def to_wire_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"status": self.status.to_dict()}
        if self.key_handle is not None:
            payload["key_handle_b64"] = _bytes_to_b64(self.key_handle)
        return {
            "direction": "response",
            "operation": Operation.QKD_OPEN.value,
            "payload": payload,
        }

    @classmethod
    def from_wire_dict(cls, data: Dict[str, Any]) -> "QKDOpenResponse":
        payload = data["payload"]
        key_handle = (
            _b64_to_bytes(payload["key_handle_b64"])
            if "key_handle_b64" in payload
            else None
        )
        return cls(status=Status.from_dict(payload["status"]), key_handle=key_handle)


@dataclass(frozen=True)
class QKDConnectNonBlockRequest:
    key_handle: bytes

    def __post_init__(self) -> None:
        _validate_key_handle(self.key_handle)

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "direction": "request",
            "operation": Operation.QKD_CONNECT_NONBLOCK.value,
            "payload": {"key_handle_b64": _bytes_to_b64(self.key_handle)},
        }

    @classmethod
    def from_wire_dict(cls, data: Dict[str, Any]) -> "QKDConnectNonBlockRequest":
        payload = data["payload"]
        return cls(key_handle=_b64_to_bytes(payload["key_handle_b64"]))


@dataclass(frozen=True)
class QKDConnectNonBlockResponse:
    status: Status
    synchronized: bool

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "direction": "response",
            "operation": Operation.QKD_CONNECT_NONBLOCK.value,
            "payload": {
                "status": self.status.to_dict(),
                "synchronized": self.synchronized,
            },
        }

    @classmethod
    def from_wire_dict(cls, data: Dict[str, Any]) -> "QKDConnectNonBlockResponse":
        payload = data["payload"]
        return cls(
            status=Status.from_dict(payload["status"]),
            synchronized=payload["synchronized"],
        )


@dataclass(frozen=True)
class QKDConnectBlockingRequest:
    key_handle: bytes
    timeout_ms: int

    def __post_init__(self) -> None:
        _validate_key_handle(self.key_handle)
        if self.timeout_ms < 0:
            raise ValueError("timeout_ms must be >= 0")

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "direction": "request",
            "operation": Operation.QKD_CONNECT_BLOCKING.value,
            "payload": {
                "key_handle_b64": _bytes_to_b64(self.key_handle),
                "timeout_ms": self.timeout_ms,
            },
        }

    @classmethod
    def from_wire_dict(cls, data: Dict[str, Any]) -> "QKDConnectBlockingRequest":
        payload = data["payload"]
        return cls(
            key_handle=_b64_to_bytes(payload["key_handle_b64"]),
            timeout_ms=payload["timeout_ms"],
        )


@dataclass(frozen=True)
class QKDConnectBlockingResponse:
    status: Status
    synchronized: bool

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "direction": "response",
            "operation": Operation.QKD_CONNECT_BLOCKING.value,
            "payload": {
                "status": self.status.to_dict(),
                "synchronized": self.synchronized,
            },
        }

    @classmethod
    def from_wire_dict(cls, data: Dict[str, Any]) -> "QKDConnectBlockingResponse":
        payload = data["payload"]
        return cls(
            status=Status.from_dict(payload["status"]),
            synchronized=payload["synchronized"],
        )


@dataclass(frozen=True)
class QKDGetKeyRequest:
    key_handle: bytes
    key_size_bytes: int

    def __post_init__(self) -> None:
        _validate_key_handle(self.key_handle)
        if self.key_size_bytes <= 0:
            raise ValueError("key_size_bytes must be > 0")

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "direction": "request",
            "operation": Operation.QKD_GET_KEY.value,
            "payload": {
                "key_handle_b64": _bytes_to_b64(self.key_handle),
                "key_size_bytes": self.key_size_bytes,
            },
        }

    @classmethod
    def from_wire_dict(cls, data: Dict[str, Any]) -> "QKDGetKeyRequest":
        payload = data["payload"]
        return cls(
            key_handle=_b64_to_bytes(payload["key_handle_b64"]),
            key_size_bytes=payload["key_size_bytes"],
        )


@dataclass(frozen=True)
class QKDGetKeyResponse:
    status: Status
    key_buffer: bytes

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "direction": "response",
            "operation": Operation.QKD_GET_KEY.value,
            "payload": {
                "status": self.status.to_dict(),
                "key_buffer_b64": _bytes_to_b64(self.key_buffer),
            },
        }

    @classmethod
    def from_wire_dict(cls, data: Dict[str, Any]) -> "QKDGetKeyResponse":
        payload = data["payload"]
        return cls(
            status=Status.from_dict(payload["status"]),
            key_buffer=_b64_to_bytes(payload["key_buffer_b64"]),
        )


@dataclass(frozen=True)
class QKDCloseRequest:
    key_handle: bytes

    def __post_init__(self) -> None:
        _validate_key_handle(self.key_handle)

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "direction": "request",
            "operation": Operation.QKD_CLOSE.value,
            "payload": {"key_handle_b64": _bytes_to_b64(self.key_handle)},
        }

    @classmethod
    def from_wire_dict(cls, data: Dict[str, Any]) -> "QKDCloseRequest":
        payload = data["payload"]
        return cls(key_handle=_b64_to_bytes(payload["key_handle_b64"]))


@dataclass(frozen=True)
class QKDCloseResponse:
    status: Status

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            "direction": "response",
            "operation": Operation.QKD_CLOSE.value,
            "payload": {"status": self.status.to_dict()},
        }

    @classmethod
    def from_wire_dict(cls, data: Dict[str, Any]) -> "QKDCloseResponse":
        payload = data["payload"]
        return cls(status=Status.from_dict(payload["status"]))


RequestType = Union[
    QKDOpenRequest,
    QKDConnectNonBlockRequest,
    QKDConnectBlockingRequest,
    QKDGetKeyRequest,
    QKDCloseRequest,
]

ResponseType = Union[
    QKDOpenResponse,
    QKDConnectNonBlockResponse,
    QKDConnectBlockingResponse,
    QKDGetKeyResponse,
    QKDCloseResponse,
]

WireMessageType = Union[RequestType, ResponseType]


_request_registry: Dict[Operation, Type[Any]] = {
    Operation.QKD_OPEN: QKDOpenRequest,
    Operation.QKD_CONNECT_NONBLOCK: QKDConnectNonBlockRequest,
    Operation.QKD_CONNECT_BLOCKING: QKDConnectBlockingRequest,
    Operation.QKD_GET_KEY: QKDGetKeyRequest,
    Operation.QKD_CLOSE: QKDCloseRequest,
}

_response_registry: Dict[Operation, Type[Any]] = {
    Operation.QKD_OPEN: QKDOpenResponse,
    Operation.QKD_CONNECT_NONBLOCK: QKDConnectNonBlockResponse,
    Operation.QKD_CONNECT_BLOCKING: QKDConnectBlockingResponse,
    Operation.QKD_GET_KEY: QKDGetKeyResponse,
    Operation.QKD_CLOSE: QKDCloseResponse,
}

def encode_message(message: WireMessageType) -> str:
    return json.dumps(message.to_wire_dict(), separators=(",", ":"), sort_keys=True)


def decode_message(raw_message: str) -> WireMessageType:
    data = json.loads(raw_message)
    direction = data.get("direction")
    operation = Operation(data["operation"])

    if direction == "request":
        message_cls = _request_registry[operation]
    elif direction == "response":
        message_cls = _response_registry[operation]
    else:
        raise ValueError(f"Unsupported direction: {direction}")

    return message_cls.from_wire_dict(data)
