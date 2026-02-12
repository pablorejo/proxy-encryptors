from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import urllib.error
import urllib.request
import uuid
from typing import Any, Tuple

LOGGER = logging.getLogger("qkd004.handler")


def _is_enabled_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _load_etsi014_types() -> Tuple[Any, Any, Any, Any]:
    """
    Lazy import so proxy can still boot even if optional ETSI014 deps are missing.
    """
    from ETSIQKD.ETSI014 import (  # pylint: disable=import-outside-toplevel
        ETSI014_Key,
        ETSI014_KeyContainer,
        ETSI014_KeyRequest,
        ETSI014_getKey,
    )

    return ETSI014_getKey, ETSI014_KeyRequest, ETSI014_KeyContainer, ETSI014_Key


def _build_local_key_container(key_size_bytes: int) -> Any:
    """
    Build a local ETSI014-shaped response when no remote KME host is configured.
    """
    _, _, ETSI014_KeyContainer, ETSI014_Key = _load_etsi014_types()
    raw_key = os.urandom(key_size_bytes)
    key_model = ETSI014_Key(key_ID=uuid.uuid4(), key=base64.b64encode(raw_key))
    return ETSI014_KeyContainer(keys=[key_model])


def _build_ssl_context() -> ssl.SSLContext:
    """
    Build SSL context for ETSI014 HTTP calls.

    Supported env vars:
    - ETSI014_CA_CERT_FILE: path to CA bundle/certificate in PEM.
    - ETSI014_CA_CERT_PATH: path to directory of trusted CA certs.
    - ETSI014_CLIENT_CERT_FILE: client certificate (PEM) for mTLS.
    - ETSI014_CLIENT_KEY_FILE: client private key (PEM) for mTLS.
    - ETSI014_CLIENT_KEY_PASSWORD: optional password for private key.
    - ETSI014_DISABLE_X509_STRICT: disable OpenSSL X509 strict checks (compat mode).
    - ETSI014_INSECURE_SKIP_VERIFY: disable TLS verification (debug only).
    """
    insecure = _is_enabled_flag("ETSI014_INSECURE_SKIP_VERIFY", "false")
    if insecure:
        context = ssl._create_unverified_context()
        context.check_hostname = False
        return context

    ca_file = os.getenv("ETSI014_CA_CERT_FILE", "").strip() or None
    ca_path = os.getenv("ETSI014_CA_CERT_PATH", "").strip() or None
    try:
        context = ssl.create_default_context(cafile=ca_file, capath=ca_path)
    except Exception as exc:
        raise RuntimeError(f"invalid ETSI014 CA certificate configuration: {exc}") from exc

    # Python/OpenSSL can reject otherwise valid legacy CAs when X509 strict mode is on.
    # Keep verification enabled but relax strict extension checks for interoperability.
    disable_x509_strict = _is_enabled_flag("ETSI014_DISABLE_X509_STRICT", "true")
    if disable_x509_strict and hasattr(ssl, "VERIFY_X509_STRICT"):
        try:
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        except Exception as exc:
            LOGGER.warning("unable to disable VERIFY_X509_STRICT: %s", exc)

    client_cert_file = os.getenv("ETSI014_CLIENT_CERT_FILE", "").strip()
    client_key_file = os.getenv("ETSI014_CLIENT_KEY_FILE", "").strip() or None
    client_key_password = os.getenv("ETSI014_CLIENT_KEY_PASSWORD", "").strip() or None

    if client_cert_file:
        try:
            context.load_cert_chain(
                certfile=client_cert_file,
                keyfile=client_key_file,
                password=client_key_password,
            )
        except Exception as exc:
            raise RuntimeError(f"invalid ETSI014 client certificate configuration: {exc}") from exc

    return context


def _request_key_container_from_kme(key_size_bytes: int) -> Any:
    """
    Call an ETSI014 KME endpoint and parse response as ETSI014_KeyContainer.

    Required env vars:
    - ETSI014_HOST: Base URL, example https://kme.example
    - ETSI014_SAE_ID: SAE identifier used in path

    Optional TLS env vars:
    - ETSI014_CA_CERT_FILE, ETSI014_CA_CERT_PATH
    - ETSI014_CLIENT_CERT_FILE, ETSI014_CLIENT_KEY_FILE, ETSI014_CLIENT_KEY_PASSWORD
    - ETSI014_INSECURE_SKIP_VERIFY
    """
    ETSI014_getKey, ETSI014_KeyRequest, ETSI014_KeyContainer, _ = _load_etsi014_types()

    host = os.getenv("ETSI014_HOST", "").strip()
    sae_id = os.getenv("ETSI014_SAE_ID", "").strip()
    if not host or not sae_id:
        raise RuntimeError("ETSI014_HOST and ETSI014_SAE_ID must be configured")

    timeout_seconds = float(os.getenv("ETSI014_TIMEOUT_SECONDS", "5"))
    size_in_bits = _is_enabled_flag("ETSI014_SIZE_IN_BITS", "true")
    etsi_size = key_size_bytes * 8 if size_in_bits else key_size_bytes

    request_message = ETSI014_getKey(
        SAE_id=sae_id,
        request=ETSI014_KeyRequest(number=1, size=etsi_size),
    )
    endpoint_url = request_message.get_endpoint_url(host.rstrip("/"))
    body = request_message.to_json().encode("utf-8")

    headers = {"Content-Type": "application/json"}
    token = os.getenv("ETSI014_AUTH_BEARER", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        endpoint_url,
        data=body,
        headers=headers,
        method=request_message.access_method,
    )
    ssl_context = _build_ssl_context()

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout_seconds,
            context=ssl_context,
        ) as response:
            payload = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        error_payload = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"ETSI014 KME HTTP {exc.code}: {error_payload}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"ETSI014 KME connection error: {exc}") from exc

    try:
        response_data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ETSI014 KME returned invalid JSON") from exc

    # Accept either a bare KeyContainer or one nested under 'key_container'
    container_data = response_data.get("key_container", response_data)
    return ETSI014_KeyContainer.from_json(container_data)


def _extract_key_bytes(container: Any) -> bytes:
    """
    Extract first key bytes from ETSI014_KeyContainer.
    """
    keys = container.get_keys() if hasattr(container, "get_keys") else getattr(container, "keys", [])
    if not keys:
        raise RuntimeError("ETSI014 key container is empty")

    first_key = keys[0]
    key_value = getattr(first_key, "key", None)
    if isinstance(key_value, (bytes, bytearray)):
        return bytes(key_value)

    # Pydantic model_dump fallback.
    if hasattr(first_key, "model_dump"):
        dumped = first_key.model_dump()
        dumped_key = dumped.get("key")
        if isinstance(dumped_key, (bytes, bytearray)):
            return bytes(dumped_key)
        if isinstance(dumped_key, str):
            return base64.b64decode(dumped_key)

    raise RuntimeError("Unable to decode key bytes from ETSI014 key container")


def get_key(key_size_bytes: int) -> bytes:
    """
    Retrieve key material using ETSI014 models.

    Behavior:
    - If ETSI014_HOST + ETSI014_SAE_ID are set: call remote KME (ETSI014 /enc_keys).
    - Otherwise: build a local ETSI014 key container and return one key from it.
    - If ETSI014 dependencies are unavailable, optionally fallback to os.urandom.
    """
    if key_size_bytes <= 0:
        raise ValueError("key_size_bytes must be > 0")

    allow_random_fallback = _is_enabled_flag("ETSI014_ALLOW_RANDOM_FALLBACK", "true")

    try:
        host = os.getenv("ETSI014_HOST", "").strip()
        sae_id = os.getenv("ETSI014_SAE_ID", "").strip()
        if host and sae_id:
            container = _request_key_container_from_kme(key_size_bytes)
        else:
            container = _build_local_key_container(key_size_bytes)

        key_material = _extract_key_bytes(container)
        if len(key_material) != key_size_bytes:
            raise RuntimeError(
                f"ETSI014 key length mismatch: expected {key_size_bytes}, got {len(key_material)}"
            )
        return key_material
    except Exception as exc:
        if allow_random_fallback:
            LOGGER.warning("ETSI014 key retrieval failed, using random fallback: %s", exc)
            return os.urandom(key_size_bytes)
        raise
