# proxy-encryptors

Proxy ETSI GS QKD 004 sobre TCP que obtiene material de clave desde una KME ETSI014 y lo entrega a clientes ETSI004.

## Descripción breve del proyecto

Este proyecto implementa un servicio `proxy.py` que:

- Escucha peticiones ETSI004 (`QKD_OPEN`, `QKD_CONNECT_*`, `QKD_GET_KEY`, `QKD_CLOSE`) en TCP con JSON delimitado por línea.
- Escucha peticiones binarias HQS (`InitializeCommunication`, `GetStatus`, `GetKey`, `TerminateCommunication`, `GetRandomNumber`) según `HQSInterface2.proto`.
- Traduce la obtención de clave (`QKD_GET_KEY`) a una llamada ETSI014 (`/api/v1/keys/{SAE_ID}/enc_keys`) usando mTLS.
- Mantiene una caché por `key_handle` para poder devolver la misma clave en múltiples `QKD_GET_KEY` del mismo flujo.

También incluye:

- `etsi004_client.py`: cliente de pruebas para hablar con el proxy.
- `handler.py`: lógica ETSI014 (TLS, request/response, parseo de clave).
- `config.json`: configuración de KMEs y certificados.

## Cómo se despliega

### Requisitos

- Python 3.13+ (recomendado el `venv` del proyecto).
- Dependencias Python:
  - `pydantic>=2,<3`
- Certificados en `certs/` (cliente SAE + CA de servidor de QuKayDee).

### Instalación

```bash
python -m venv venv
./venv/bin/pip install "pydantic>=2,<3"
```

### Arranque del proxy

```bash
./venv/bin/python proxy.py \
  --config config.json \
  --local-kme alice \
  --remote-kme bob \
  --host 0.0.0.0 \
  --port 5000 \
  --verbose
```

### Trazas y diagnóstico

- `--verbose`: activa logs `DEBUG` (parseo, estado interno, cache-hit/miss, rutas ETSI014).
- `--trace-wire`: además imprime payloads de red (hex/ascii) para JSON y binario HQS.
- `--trace-limit N`: limita bytes mostrados por payload en `--trace-wire`.

Ejemplo de depuración máxima:

```bash
./venv/bin/python proxy.py \
  --config config.json \
  --local-kme alice \
  --remote-kme bob \
  --host 0.0.0.0 \
  --port 5000 \
  --verbose \
  --trace-wire \
  --trace-limit 512
```

### Lanzar un cliente ETSI004

```bash
./venv/bin/python etsi004_client.py \
  --host 127.0.0.1 \
  --port 5000 \
  --connect-mode nonblock \
  --show-raw
```

## Cómo funciona internamente el proxy

### Flujo ETSI004 en el proxy

1. `QKD_OPEN`
- Crea una asociación interna y devuelve `key_handle`.

2. `QKD_CONNECT_NONBLOCK` / `QKD_CONNECT_BLOCKING`
- Verifica si la asociación existe para ese `key_handle`.

3. `QKD_GET_KEY`
- Si es la primera vez para ese `key_handle`, llama a `handler.get_key(...)`.
- `handler.get_key(...)` construye y envía petición ETSI014 `enc_keys` al host KME configurado.
- La clave recibida se guarda en caché (`_key_cache[key_handle] = key_material`).
- Si llega otro `QKD_GET_KEY` con el mismo `key_handle` y mismo tamaño, devuelve exactamente la misma clave desde caché.

4. `QKD_CLOSE`
- Borra asociación y caché de ese `key_handle`.

### Gestión de la misma clave entre dos clientes ETSI004

La igualdad de clave entre dos clientes se consigue compartiendo el mismo `key_handle`.

Flujo recomendado:

1. Cliente A ejecuta `QKD_OPEN` + `QKD_GET_KEY` con `--no-close`.
2. Cliente A comparte `key_handle_b64` con Cliente B (canal externo seguro).
3. Cliente B usa `--reuse-key-handle-b64 "..."` y pide `QKD_GET_KEY`.
4. El proxy devuelve la misma clave porque lee la caché de ese `key_handle`.
5. Al final, uno de los dos hace `QKD_CLOSE`.

Ejemplo real con el cliente incluido:

```bash
# Cliente A: abre y no cierra
./venv/bin/python etsi004_client.py --host 127.0.0.1 --port 5000 --no-close
# salida: key_handle_b64=...

# Cliente B: reutiliza el mismo handle
./venv/bin/python etsi004_client.py --host 127.0.0.1 --port 5000 --reuse-key-handle-b64 "<key_handle_b64>"
```

Notas importantes:

- Ambos clientes deben pedir el mismo `--key-size` para ese `key_handle`.
- Si cambias el tamaño de clave con el mismo handle, el proxy responde `INVALID_ARGUMENT`.
- Si se cerró (`QKD_CLOSE`), ese handle deja de ser válido.

## Cómo configurar `config.json`

`proxy.py` carga este archivo al arrancar y de ahí construye la configuración ETSI014 (`host`, `SAE_ID`, certificados, CA).

### Estructura mínima

```json
{
  "ca-cert": "certs/account-2576-server-ca-qukaydee-com.crt",
  "kmes": [
    {
      "name": "alice",
      "url": "https://kme-1.acct-2576.etsi-qkd-api.qukaydee.com",
      "crt": "certs/sae-1.crt",
      "key": "certs/sae-1.key",
      "pem": "certs/sae-1.pem"
    },
    {
      "name": "bob",
      "url": "https://kme-2.acct-2576.etsi-qkd-api.qukaydee.com",
      "crt": "certs/sae-2.crt",
      "key": "certs/sae-2.key",
      "pem": "certs/sae-2.pem"
    }
  ]
}
```

### Campos soportados

Top-level:

- `kmes` (obligatorio): lista de KMEs.
- `ca`, `ca_cert` o `ca-cert` (opcional): CA de servidor TLS.
- `remote_sae_id` o `remote-sae-id` (opcional): SAE remoto explícito.
- `allow_random_fallback` o `allow-random-fallback` (opcional, bool): fallback a clave aleatoria si ETSI014 falla.

Por KME:

- `name` (recomendado): nombre lógico (`alice`, `bob`, etc.).
- `url` (obligatorio): base URL de la KME.
- `crt` o `cert` o `pem` (obligatorio al menos uno): certificado cliente.
- `key` (opcional): clave privada si no viene dentro del `pem`.
- `sae_id` o `sae-id` (opcional): SAE remoto asociado.
- `ca`, `ca_cert` o `ca-cert` (opcional): CA específica por KME.

### Selección de KME local/remoto

- `--local-kme`: KME desde la que este proxy pide claves.
- `--remote-kme`: SAE/KME remota para el endpoint ETSI014.

Si no los pasas:

- Local: primer elemento de `kmes`.
- Remoto: el otro elemento (si existe).

### TLS y compatibilidad

- El proxy usa verificación TLS con CA y mTLS cliente.
- Para compatibilidad con algunos certificados legacy, el código desactiva `VERIFY_X509_STRICT` por defecto (`ETSI014_DISABLE_X509_STRICT=true`) manteniendo la validación de certificado activa.
- Solo para pruebas, puedes desactivar verificación completa con `ETSI014_INSECURE_SKIP_VERIFY=true` (no recomendado en producción).
