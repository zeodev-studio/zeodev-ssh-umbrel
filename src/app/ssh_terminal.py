"""Paramiko SSH shell adapter. Credentials never touch persistent storage."""
from __future__ import annotations

import base64
import hashlib
import io
import socket


class TrustRequired(Exception):
    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint
        super().__init__('Host key must be verified')


class HostKeyChanged(Exception):
    pass


def _read_key(paramiko, private_key: str, passphrase: str | None):
    for key_class in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return key_class.from_private_key(io.StringIO(private_key), password=passphrase or None)
        except paramiko.PasswordRequiredException:
            raise ValueError('Klucz jest zaszyfrowany — podaj hasło do klucza SSH')
        except (paramiko.SSHException, ValueError):
            continue
    raise ValueError('Nieobsługiwany albo niepoprawny klucz prywatny SSH')


def connect_shell(host: dict, credentials: dict, approved_fingerprint: str | None):
    import paramiko

    sock = None
    transport = None
    try:
        sock = socket.create_connection((host['address'], host['port']), timeout=8)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = 10
        transport.auth_timeout = 15
        transport.start_client(timeout=12)
        remote_key = transport.get_remote_server_key()
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(remote_key.asbytes()).digest()).decode().rstrip('=')
        pinned = host.get('fingerprint')
        if pinned and pinned != fingerprint:
            raise HostKeyChanged('Klucz serwera zmienił się! Nie łączę ze względów bezpieczeństwa.')
        if not pinned and approved_fingerprint != fingerprint:
            raise TrustRequired(fingerprint)

        method = credentials.get('authType')
        if method == 'password':
            password = credentials.get('password')
            if not isinstance(password, str) or not password:
                raise ValueError('Wpisz hasło SSH')
            transport.auth_password(host['username'], password)
        elif method == 'privateKey':
            private_key = credentials.get('privateKey')
            if not isinstance(private_key, str) or len(private_key) > 100_000:
                raise ValueError('Wklej prawidłowy klucz prywatny SSH')
            pkey = _read_key(paramiko, private_key, credentials.get('passphrase'))
            transport.auth_publickey(host['username'], pkey)
        else:
            raise ValueError('Wybierz metodę logowania')

        if not transport.is_authenticated():
            raise ValueError('Serwer odrzucił uwierzytelnianie')
        channel = transport.open_session(timeout=10)
        channel.get_pty(term='xterm-256color', width=100, height=30)
        channel.invoke_shell()
        channel.settimeout(1)
        return transport, channel, fingerprint
    except Exception:
        if transport:
            transport.close()
        elif sock:
            sock.close()
        raise
