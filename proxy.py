#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import os
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

    def handle(self) -> None:
        if self.service is None:
            raise RuntimeError("QKDProxyService is not configured")

        client = f"{self.client_address[0]}:{self.client_address[1]}"
        LOGGER.info("Connection from %s", client)

        for raw_line in self.rfile:
            raw_message = raw_line.decode("utf-8").strip()
            if not raw_message:
                continue

            response = self.service.handle_raw_message(raw_message)
            self.wfile.write((response + "\n").encode("utf-8"))
            self.wfile.flush()

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


def run_server(host: str, port: int) -> None:
    service = QKDProxyService()

    class BoundHandler(QKDProxyTCPHandler):
        pass

    BoundHandler.service = service

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
    run_server(args.host, args.port)


if __name__ == "__main__":
    main()
