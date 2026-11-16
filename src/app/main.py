"""ZeoDev SSH: local SSH host manager and bounded LAN discovery."""
from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import store, discovery

COOKIE_NAME = 'zeodev_session'
STATIC = Path(__file__).parent / 'static'
ACTIVE_SESSIONS: dict[str, dict] = {}
LOGIN_ATTEMPTS: dict[str, deque] = defaultdict(deque)
SCAN_LOCK = asyncio.Lock()
SCAN_ACTIVE = False
BACKGROUND_TASK: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global BACKGROUND_TASK
    store.prepare()
    store.ensure_discovery_tables()
    if not store.has_admin():
        # Provision a unique initial password in install.sh, never use a universal default.
        initial_password = os.environ.get('ZEODEV_ADMIN_PASSWORD', '')
        if len(initial_password) >= 16:
            store.create_admin(initial_password)
        elif os.environ.get('ZEODEV_ALLOW_WEB_SETUP', '').lower() != 'true':
            raise RuntimeError('Set ZEODEV_ADMIN_PASSWORD or explicitly enable the authenticated first-run setup')
    initial_networks = os.environ.get('ZEODEV_SCAN_CIDRS', '').strip()
    if initial_networks and not store.get_scan_settings()['cidrs']:
        store.set_scan_settings(discovery.validate_networks(initial_networks))
    BACKGROUND_TASK = asyncio.create_task(_scan_loop())
    try:
        yield
    finally:
        BACKGROUND_TASK.cancel()
        await asyncio.gather(BACKGROUND_TASK, return_exceptions=True)


async def _scan_loop():
    # Initial scan + periodic refresh. Only stored, validated RFC1918 networks.
    while True:
        try:
            await run_discovery()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Error recorded by next manual retry; keep the server available.
            pass
        await asyncio.sleep(180)


async def run_discovery() -> dict:
    global SCAN_ACTIVE
    if SCAN_LOCK.locked():
        return {'running': True}
    async with SCAN_LOCK:
        SCAN_ACTIVE = True
        try:
            value = store.get_scan_settings()['cidrs']
            if not value:
                return {'running': False, 'found': 0, 'message': 'Skonfiguruj sieć do skanowania'}
            addresses, found = await discovery.scan_networks(value)
            store.record_scan(addresses, found)
            return {'running': False, 'found': len(found), 'checked': len(addresses)}
        finally:
            SCAN_ACTIVE = False


app = FastAPI(title='ZeoDev SSH', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount('/static', StaticFiles(directory=STATIC), name='static')


class LoginBody(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordBody(BaseModel):
    currentPassword: str = Field(min_length=1, max_length=256)
    newPassword: str = Field(min_length=16, max_length=256)


class ScanSettingsBody(BaseModel):
    cidrs: str = Field(max_length=160)


class HostBody(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=64)

    @field_validator('name', 'username', 'address')
    @classmethod
    def clean(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError('Niedozwolone znaki')
        return value

    @field_validator('address')
    @classmethod
    def address_valid(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
                raise ValueError('Wpisz adres IP lub nazwę DNS (bez http://)')
        return value

    @field_validator('username')
    @classmethod
    def username_valid(cls, value: str) -> str:
        if not re.fullmatch(r'[A-Za-z0-9_.@-]+', value):
            raise ValueError('Niepoprawna nazwa użytkownika')
        return value


def error(message: str, code: int = 400):
    return JSONResponse({'error': message}, status_code=code)


def _origin_ok(origin: str | None, host: str | None) -> bool:
    if not origin or not host:
        return False
    parsed = urlparse(origin)
    return parsed.scheme in ('http', 'https') and hmac.compare_digest(parsed.netloc.lower(), host.lower())


def _admin(request: Request) -> bool:
    return store.verify_session(request.cookies.get(COOKIE_NAME))


@app.middleware('http')
async def secure_requests(request: Request, call_next):
    path = request.url.path
    if request.method not in ('GET', 'HEAD', 'OPTIONS') and path.startswith('/api/'):
        # Sessions are cookie-based: reject cross-origin write attempts.
        if not _origin_ok(request.headers.get('origin'), request.headers.get('host')):
            return error('Niedozwolone pochodzenie żądania', 403)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    response.headers['Cache-Control'] = 'no-store' if path.startswith('/api/') else 'private, max-age=0'
    return response


@app.get('/health')
def health():
    return {'status': 'ok', 'app': 'zeodev-ssh'}


@app.get('/api/setup')
def setup_status(request: Request):
    return {'needsSetup': not store.has_admin(), 'authenticated': _admin(request)}


def session_response(request: Request):
    response = JSONResponse({'ok': True})
    # Umbrel can serve HTTP on LAN; cookie is secure whenever served through HTTPS.
    forwarded = request.headers.get('x-forwarded-proto', '')
    secure = request.url.scheme == 'https' or forwarded.split(',')[0].strip() == 'https'
    response.set_cookie(COOKIE_NAME, store.issue_session(), httponly=True, samesite='strict', secure=secure,
                        max_age=12*3600, path='/')
    return response




class InitializeBody(BaseModel):
    password: str = Field(min_length=16, max_length=256)


@app.post('/api/initialize')
def initialize(body: InitializeBody, request: Request):
    # Only enable this mode behind Umbrel's authenticated app_proxy.
    if os.environ.get('ZEODEV_ALLOW_WEB_SETUP', '').lower() != 'true':
        return error('Konfiguracja przez przeglądarkę jest wyłączona', 403)
    if not store.create_admin(body.password):
        return error('Administrator jest już skonfigurowany', 409)
    return session_response(request)


@app.post('/api/login')
def login(body: LoginBody, request: Request):
    address = request.client.host if request.client else 'unknown'
    now = time.monotonic()
    recent = LOGIN_ATTEMPTS[address]
    while recent and recent[0] < now - 300:
        recent.popleft()
    if len(recent) >= 10:
        return error('Zbyt wiele prób. Spróbuj ponownie później.', 429)
    if not store.check_admin(body.password):
        recent.append(now)
        return error('Niepoprawne hasło', 401)
    recent.clear()
    return session_response(request)


@app.post('/api/logout')
def logout(request: Request):
    if not _admin(request):
        return error('Zaloguj się', 401)
    response = JSONResponse({'ok': True})
    response.delete_cookie(COOKIE_NAME, path='/')
    return response


@app.post('/api/change-password')
def change_password(body: ChangePasswordBody, request: Request):
    if not _admin(request):
        return error('Zaloguj się', 401)
    if not store.check_admin(body.currentPassword):
        return error('Błędne aktualne hasło', 403)
    store.replace_admin_password(body.newPassword)
    return {'ok': True}


@app.get('/api/discovery')
def discovered_hosts(request: Request):
    if not _admin(request):
        return error('Zaloguj się', 401)
    return {'devices': store.list_discovered(), 'settings': store.get_scan_settings(), 'scanning': SCAN_ACTIVE}


@app.put('/api/discovery/settings')
def scan_settings(body: ScanSettingsBody, request: Request):
    if not _admin(request):
        return error('Zaloguj się', 401)
    try:
        cidrs = discovery.validate_networks(body.cidrs)
    except ValueError as exc:
        return error(str(exc), 422)
    store.set_scan_settings(cidrs)
    return store.get_scan_settings()


@app.post('/api/discovery/scan')
async def scan_now(request: Request):
    if not _admin(request):
        return error('Zaloguj się', 401)
    return await run_discovery()


@app.get('/api/hosts')
def hosts(request: Request):
    if not _admin(request):
        return error('Zaloguj się', 401)
    return {'hosts': store.list_hosts()}


@app.post('/api/hosts')
def create_host(body: HostBody, request: Request):
    if not _admin(request):
        return error('Zaloguj się', 401)
    return JSONResponse(store.add_host(body.model_dump()), status_code=201)


@app.put('/api/hosts/{host_id}')
def update_host(host_id: str, body: HostBody, request: Request):
    if not _admin(request):
        return error('Zaloguj się', 401)
    updated = store.edit_host(host_id, body.model_dump())
    return updated if updated else error('Urządzenia nie znaleziono', 404)


@app.delete('/api/hosts/{host_id}')
def remove_host(host_id: str, request: Request):
    if not _admin(request):
        return error('Zaloguj się', 401)
    if any(session['hostId'] == host_id for session in ACTIVE_SESSIONS.values()):
        return error('Zamknij aktywne sesje przed usunięciem urządzenia', 409)
    return {'ok': store.delete_host(host_id)}


@app.post('/api/hosts/{host_id}/reset-fingerprint')
def remove_fingerprint(host_id: str, request: Request):
    if not _admin(request):
        return error('Zaloguj się', 401)
    if any(session['hostId'] == host_id for session in ACTIVE_SESSIONS.values()):
        return error('Zamknij aktywne sesje przed zmianą klucza hosta', 409)
    if not store.reset_fingerprint(host_id):
        return error('Nie znaleziono', 404)
    return {'ok': True}


async def probe(host: dict) -> dict:
    checked = await discovery.probe_ssh(host['address'], host['port'], timeout=1.3)
    return {'id': host['id'], 'reachable': checked.reachable}


@app.get('/api/status')
async def host_status(request: Request):
    if not _admin(request):
        return error('Brak dostępu', 401)
    results = await asyncio.gather(*(probe(host) for host in store.list_hosts()))
    return {'hosts': results, 'sessions': list(ACTIVE_SESSIONS.values())}


@app.websocket('/ws/terminal')
async def terminal(ws: WebSocket):
    if not _origin_ok(ws.headers.get('origin'), ws.headers.get('host')) or not store.verify_session(ws.cookies.get(COOKIE_NAME)):
        await ws.close(code=1008)
        return
    if len(ACTIVE_SESSIONS) >= 10:
        await ws.close(code=1013)
        return
    await ws.accept()
    transport = None
    channel = None
    session_id = None
    try:
        data = await asyncio.wait_for(ws.receive_json(), timeout=30)
        host_id = data.get('hostId')
        host = store.get_host(host_id) if isinstance(host_id, str) else None
        if not host:
            await ws.send_json({'type':'error','message':'Urządzenie nie istnieje'})
            return
        credentials = {
            'authType': data.get('authType'), 'password': data.get('password'),
            'privateKey': data.get('privateKey'), 'passphrase': data.get('passphrase'),
        }
        from .ssh_terminal import connect_shell, TrustRequired, HostKeyChanged
        try:
            transport, channel, fingerprint = await asyncio.to_thread(connect_shell, host, credentials, None)
        except TrustRequired as untrusted:
            await ws.send_json({'type': 'trust_required', 'fingerprint': untrusted.fingerprint})
            response = await asyncio.wait_for(ws.receive_json(), timeout=90)
            if response.get('type') != 'trust' or response.get('fingerprint') != untrusted.fingerprint:
                await ws.send_json({'type':'error','message':'Nie zatwierdzono klucza hosta'})
                return
            transport, channel, fingerprint = await asyncio.to_thread(connect_shell, host, credentials, untrusted.fingerprint)
        except HostKeyChanged as exc:
            await ws.send_json({'type':'error','message':str(exc)})
            return
        if not store.pin_fingerprint(host_id, fingerprint):
            await ws.send_json({'type':'error','message':'Nie udało się zapisać klucza hosta'})
            return
        session_id = secrets.token_urlsafe(16)
        ACTIVE_SESSIONS[session_id] = {'id':session_id, 'hostId':host_id, 'name':host['name'], 'startedAt':int(time.time())}
        await ws.send_json({'type':'connected','sessionId':session_id})

        async def read_remote():
            while transport and transport.is_active() and channel and not channel.closed:
                try:
                    chunk = await asyncio.to_thread(channel.recv, 8192)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                await ws.send_bytes(chunk)

        async def write_remote():
            while True:
                msg = await ws.receive()
                if msg['type'] == 'websocket.disconnect':
                    break
                if msg.get('bytes'):
                    payload = msg['bytes'][:65536]
                    await asyncio.to_thread(channel.sendall, payload)
                elif msg.get('text'):
                    try:
                        control = json.loads(msg['text'])
                    except ValueError:
                        continue
                    if control.get('type') == 'resize':
                        columns = max(20, min(300, int(control.get('cols', 80))))
                        rows = max(10, min(150, int(control.get('rows', 24))))
                        await asyncio.to_thread(channel.resize_pty, width=columns, height=rows)
        tasks = [asyncio.create_task(read_remote()), asyncio.create_task(write_remote())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    except Exception as exc:
        # Don't disclose internal stack traces or secret-bearing exception strings.
        message = 'Błąd połączenia SSH. Sprawdź adres, dane logowania i ustawienia SSH.'
        if isinstance(exc, (ValueError, socket.gaierror)):
            message = str(exc)
        try:
            await ws.send_json({'type':'error','message':message})
        except Exception:
            pass
    finally:
        if session_id:
            ACTIVE_SESSIONS.pop(session_id, None)
        if channel:
            channel.close()
        if transport:
            transport.close()
        try:
            await ws.close()
        except Exception:
            pass


@app.get('/manifest.webmanifest')
def manifest():
    return FileResponse(STATIC/'manifest.webmanifest', media_type='application/manifest+json')


@app.get('/')
def index():
    return FileResponse(STATIC/'index.html')
