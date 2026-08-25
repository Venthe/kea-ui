from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import csv
import json
import os
import re
import socket
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

KEA_SOCKET_PATH = os.getenv("KEA_SOCKET_PATH", "/var/run/kea/dhcp4.sock")
KEA_CONTROL_URL = os.getenv("KEA_CONTROL_URL", "").strip()
KEA_CONFIG_PATH = Path(os.getenv("KEA_CONFIG_PATH", "/config/kea-dhcp4.conf"))
LEASE_FILE_PATH = Path(os.getenv("LEASE_FILE_PATH", "/leases/dhcp4.leases"))
RESERVATIONS_PATH = Path(os.getenv("RESERVATIONS_PATH", "/data/reservations.json"))
AUTH_CONFIG_PATH = Path(os.getenv("AUTH_CONFIG_PATH", "/data/auth.json"))
KEA_TIMEOUT = float(os.getenv("KEA_TIMEOUT", "5"))
UI_USERNAME = os.getenv("KEA_UI_USERNAME", "").strip()
UI_PASSWORD = os.getenv("KEA_UI_PASSWORD", "")
UI_SESSION_SECRET = os.getenv("KEA_UI_SESSION_SECRET", "")
COOKIE_SECURE = os.getenv("KEA_UI_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}
LEASE_STATES = {
    0: "active",
    1: "declined",
    2: "expired-reclaimed",
    3: "released",
}

app = FastAPI(title="Kea UI")
templates = Jinja2Templates(directory="app/templates")
mutation_lock = asyncio.Lock()


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            json.dump(value, file, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def load_reservations() -> list[dict[str, Any]]:
    if not RESERVATIONS_PATH.exists():
        write_json_atomic(RESERVATIONS_PATH, [])
    value = read_json(RESERVATIONS_PATH)
    if not isinstance(value, list):
        raise ValueError("reservations file must contain a JSON array")
    return value


def auth_settings() -> tuple[str, str, str]:
    username, password, secret = UI_USERNAME, UI_PASSWORD, UI_SESSION_SECRET
    if AUTH_CONFIG_PATH.exists():
        config = read_json(AUTH_CONFIG_PATH)
        username = username or str(config.get("username", "")).strip()
        password = password or str(config.get("password", ""))
        secret = secret or str(config.get("session_secret", ""))
    if not secret:
        secret = hashlib.sha256(f"{username}:{password}".encode()).hexdigest()
    return username, password, secret


def session_token(username: str, secret: str) -> str:
    encoded = base64.urlsafe_b64encode(username.encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def authenticated(request: Request) -> bool:
    username, _, secret = auth_settings()
    token = request.cookies.get("kea_ui_session", "")
    expected = session_token(username, secret) if username else ""
    return bool(username and token and hmac.compare_digest(token, expected))


def load_leases() -> list[dict[str, Any]]:
    try:
        result = kea_request("lease4-get-all", allow_empty=True)
        leases = result.get("arguments", {}).get("leases", [])
        return [normalize_lease(lease) for lease in leases]
    except RuntimeError as exc:
        if "not supported" not in str(exc).lower():
            raise
    if not LEASE_FILE_PATH.exists():
        return []
    with LEASE_FILE_PATH.open(newline="", encoding="utf-8") as file:
        return [normalize_lease(lease) for lease in csv.DictReader(file)]


def normalize_lease(lease: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(lease)
    normalized["address"] = lease.get("address", lease.get("ip-address", ""))
    normalized["hwaddr"] = lease.get("hwaddr", lease.get("hw-address", ""))
    try:
        normalized["state_label"] = LEASE_STATES.get(int(lease.get("state", 0)), "unknown")
    except (TypeError, ValueError):
        normalized["state_label"] = "unknown"
    expire = lease.get("expire")
    if not expire and lease.get("cltt") is not None and lease.get("valid-lft") is not None:
        expire = int(lease["cltt"]) + int(lease["valid-lft"])
    try:
        normalized["expire_at"] = datetime.fromtimestamp(
            int(expire), datetime.now().astimezone().tzinfo
        ).strftime("%Y-%m-%d %H:%M:%S %Z") if expire else ""
    except (TypeError, ValueError, OSError):
        normalized["expire_at"] = str(expire or "")
    return normalized


def candidate_config(reservations: list[dict[str, Any]]) -> dict[str, Any]:
    config = read_json(KEA_CONFIG_PATH)
    dhcp4 = config.setdefault("Dhcp4", {})
    subnets = dhcp4.get("subnet4", [])
    reservations_by_subnet: dict[int, list[dict[str, Any]]] = {}
    for reservation in reservations:
        subnet_id = int(reservation["subnet-id"])
        reservations_by_subnet.setdefault(subnet_id, []).append(reservation)
    for subnet in subnets:
        subnet["reservations"] = [
            {key: value for key, value in reservation.items() if key != "subnet-id"}
            for reservation in reservations_by_subnet.get(int(subnet["id"]), [])
        ]
    return config


def kea_request(
    command: str,
    arguments: dict[str, Any] | None = None,
    allow_empty: bool = False,
) -> Any:
    payload: dict[str, Any] = {"command": command}
    if arguments is not None:
        payload["arguments"] = arguments
    if KEA_CONTROL_URL:
        response = httpx.post(KEA_CONTROL_URL, json=payload, timeout=KEA_TIMEOUT)
        response.raise_for_status()
        result = response.json()
        if isinstance(result, list):
            result = result[0] if result else {}
        result_code = result.get("result", 0)
        if result_code != 0 and not (allow_empty and result_code == 3):
            raise RuntimeError(result.get("text", "Kea rejected the request"))
        return result

    request = (json.dumps(payload) + "\n").encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(KEA_TIMEOUT)
        client.connect(KEA_SOCKET_PATH)
        client.sendall(request)
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
    result = json.loads(b"".join(chunks).splitlines()[0])
    result_code = result.get("result", 0)
    if result_code != 0 and not (allow_empty and result_code == 3):
        raise RuntimeError(result.get("text", "Kea rejected the request"))
    return result


def validate_reservation(
    reservation: dict[str, Any],
    config: dict[str, Any],
    existing: list[dict[str, Any]],
) -> None:
    required = ("subnet-id", "hw-address", "ip-address")
    if any(field not in reservation or not str(reservation[field]).strip() for field in required):
        raise ValueError("subnet, MAC address, and IP address are required")
    subnet_id = int(reservation["subnet-id"])
    address = ipaddress.ip_address(str(reservation["ip-address"]).strip())
    mac = str(reservation["hw-address"]).strip().lower()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError("MAC address must contain six hexadecimal octets")
    subnets = config.get("Dhcp4", {}).get("subnet4", [])
    subnet = next((item for item in subnets if int(item["id"]) == subnet_id), None)
    if subnet is None:
        raise ValueError(f"unknown subnet id: {subnet_id}")
    if address not in ipaddress.ip_network(subnet["subnet"], strict=False):
        raise ValueError("IP address is outside the selected subnet")
    for item in existing:
        if str(item.get("hw-address", "")).strip().lower() == mac:
            raise ValueError("MAC address already has a reservation")
        if item.get("ip-address") == str(address):
            raise ValueError("IP address already has a reservation")
    reservation["subnet-id"] = subnet_id
    reservation["hw-address"] = mac
    reservation["ip-address"] = str(address)
    if reservation.get("hostname"):
        reservation["hostname"] = reservation["hostname"].strip()
    else:
        reservation.pop("hostname", None)


async def apply_reservations(reservations: list[dict[str, Any]]) -> None:
    config = candidate_config(reservations)
    kea_request("config-test", {"Dhcp4": config["Dhcp4"]})
    kea_request("config-set", {"Dhcp4": config["Dhcp4"]})
    write_json_atomic(RESERVATIONS_PATH, reservations)


async def reconcile_reservations() -> None:
    while True:
        try:
            reservations = load_reservations()
            if reservations:
                await apply_reservations(reservations)
            return
        except Exception:
            await asyncio.sleep(5)


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(reconcile_reservations())


@app.middleware("http")
async def require_login(request: Request, call_next):
    if request.url.path in {"/login", "/healthz"} or authenticated(request):
        return await call_next(request)
    if request.url.path.startswith("/api/") or request.url.path == "/events":
        return HTMLResponse("Authentication required", status_code=401)
    return RedirectResponse("/login", status_code=303)


async def lease_events():
    previous: str | None = None
    while True:
        try:
            leases = await asyncio.to_thread(load_leases)
            current = json.dumps(leases, sort_keys=True)
            if current != previous:
                previous = current
                yield f"data: {current}\n\n"
        except Exception as exc:
            yield f"event: error\ndata: {json.dumps(str(exc))}\n\n"
        await asyncio.sleep(float(os.getenv("LEASE_POLL_INTERVAL", "2")))


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str | None = None) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="login.html", context={"error": error})


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse:
    configured_username, configured_password, secret = auth_settings()
    if not configured_username:
        return RedirectResponse("/login?error=No+credentials+configured", status_code=303)
    if not (
        hmac.compare_digest(username.strip(), configured_username)
        and hmac.compare_digest(password, configured_password)
    ):
        return RedirectResponse("/login?error=Invalid+credentials", status_code=303)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        "kea_ui_session",
        session_token(configured_username, secret),
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
    )
    return response


@app.post("/logout")
async def logout() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("kea_ui_session")
    return response


def kea_status() -> dict[str, Any]:
    status_result = kea_request("status-get")
    version_result = kea_request("version-get")
    config_result = kea_request("config-get")
    commands_result = kea_request("list-commands")
    dhcp4 = config_result.get("arguments", {}).get("Dhcp4", {})
    runtime = status_result.get("arguments", {})
    return {
        "version": version_result.get("text", "unknown"),
        "uptime": runtime.get("uptime", "unknown"),
        "pid": runtime.get("pid", "unknown"),
        "dhcp_state": runtime.get("dhcp-state", {}),
        "sockets": runtime.get("sockets", {}),
        "multi_threading": runtime.get("multi-threading-enabled", "unknown"),
        "thread_pool_size": runtime.get("thread-pool-size", "unknown"),
        "packet_queue_size": runtime.get("packet-queue-size", "unknown"),
        "reload": runtime.get("reload", "unknown"),
        "subnets": dhcp4.get("subnet4", []),
        "hooks": dhcp4.get("hooks-libraries", []),
        "lease_backend": dhcp4.get("lease-database", {}).get("type", "unknown"),
        "commands": commands_result.get("arguments", []),
    }


@app.get("/api/leases")
async def api_leases() -> list[dict[str, Any]]:
    return await asyncio.to_thread(load_leases)


@app.get("/events")
async def events() -> StreamingResponse:
    return StreamingResponse(lease_events(), media_type="text/event-stream")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, error: str | None = None) -> HTMLResponse:
    leases: list[dict[str, Any]] = []
    api_error = error
    try:
        leases = await asyncio.to_thread(load_leases)
    except Exception as exc:
        api_error = f"Unable to read lease file: {exc}"
    try:
        reservations = load_reservations()
    except Exception as exc:
        reservations = []
        api_error = str(exc)
    try:
        status = await asyncio.to_thread(kea_status)
    except Exception as exc:
        status = {"error": str(exc)}
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"leases": leases, "reservations": reservations, "error": api_error, "status": status},
    )


@app.post("/reservations")
async def add_reservation(
    subnet_id: str = Form(...),
    hw_address: str = Form(...),
    ip_address: str = Form(...),
    hostname: str = Form(""),
) -> RedirectResponse:
    try:
        async with mutation_lock:
            reservations = load_reservations()
            reservation: dict[str, Any] = {
                "subnet-id": subnet_id,
                "hw-address": hw_address,
                "ip-address": ip_address,
                "hostname": hostname,
            }
            config = read_json(KEA_CONFIG_PATH)
            validate_reservation(reservation, config, reservations)
            leases = await asyncio.to_thread(load_leases)
            conflicting_lease = next(
                (
                    lease for lease in leases
                    if lease.get("address") == reservation["ip-address"]
                    and lease.get("hwaddr", "").lower() != reservation["hw-address"]
                ),
                None,
            )
            if conflicting_lease:
                raise ValueError(
                    f"IP address is currently leased to {conflicting_lease.get('hwaddr', 'another client')}"
                )
            await apply_reservations(reservations + [reservation])
    except Exception as exc:
        return RedirectResponse(f"/?error={str(exc)}", status_code=303)
    return RedirectResponse("/", status_code=303)


@app.post("/reservations/delete")
async def delete_reservation(hw_address: str = Form(...)) -> RedirectResponse:
    try:
        async with mutation_lock:
            reservations = load_reservations()
            remaining = [
                item
                for item in reservations
                if str(item.get("hw-address", "")).strip().lower() != hw_address.strip().lower()
            ]
            if len(remaining) == len(reservations):
                raise ValueError("reservation not found")
            await apply_reservations(remaining)
    except Exception as exc:
        return RedirectResponse(f"/?error={str(exc)}", status_code=303)
    return RedirectResponse("/", status_code=303)


@app.post("/leases/delete")
async def delete_lease(ip_address: str = Form(...)) -> RedirectResponse:
    try:
        ipaddress.ip_address(ip_address.strip())
        kea_request("lease4-del", {"ip-address": ip_address.strip()}, allow_empty=True)
    except Exception as exc:
        return RedirectResponse(f"/?error={str(exc)}", status_code=303)
    return RedirectResponse("/", status_code=303)
