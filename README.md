# ZeoDev SSH

**Native Umbrel App Store package — not a URL shortcut.**

[![Build and publish](https://github.com/zeodev-studio/zeodev-ssh-umbrel/actions/workflows/publish.yml/badge.svg)](https://github.com/zeodev-studio/zeodev-ssh-umbrel/actions/workflows/publish.yml)

A self-hosted SSH connection manager from **ZeoDev Studio**, with saved hosts, authorized private-network discovery, server availability monitoring, a browser-based SSH terminal, and first-run administrator setup.

## Install on umbrelOS 2.0

1. Verify the [GitHub Actions build](https://github.com/zeodev-studio/zeodev-ssh-umbrel/actions/workflows/publish.yml) completed successfully.
2. Verify that the image `ghcr.io/zeodev-studio/zeodev-ssh-umbrel:0.1.1` exists and its GitHub package visibility is **Public**. A public repository by itself does not automatically make the container image public.
3. Go to **Umbrel → App Store → Community App Stores** and add `https://github.com/zeodev-studio/zeodev-ssh-umbrel`.
4. Open the **ZeoDev Studio** community store and install **ZeoDev SSH**.
5. Open the application, choose an administrator password and configure the private CIDR range that you are authorized to scan, e.g. `192.168.1.0/24`.

## Existing standalone installation

This is an **independent Umbrel-managed app**. It does **not** modify, delete, replace or migrate the previous standalone Docker container on port `8099` or the Docker volume `zeodev_ssh_data`.

The app store installation uses app port `8164` and its own persistent Umbrel data directory. Do not bind both instances to one SQLite database. Data migration can be planned after successful installation and verification.

## Repository

- `src/app/`: Python backend and browser UI.
- `src/tests/`: backend tests.
- `src/Dockerfile`: versioned application image.
- `zeodev-ssh/`: native Umbrel manifest, Docker Compose, ZeoDev brand icon.
- `umbrel-app-store.yml`: community store identity.
- `.github/workflows/publish.yml`: CI tests and AMD64/ARM64 publishing.

### Development checks

```bash
python -m pip install -r src/requirements.txt pytest pytest-asyncio httpx
cd src
python -m pytest -q tests
node --check app/static/app.js
```

## Security and current limitations

- SSH credentials are sent only to the currently opened session, not persisted in the application database.
- Unknown host keys require user approval, and pinned fingerprints prevent silent replacement.
- Discovery is restricted to configured private IPv4 networks, by default port 22; do not scan networks without authorization.
- The app lists SSH sessions opened through ZeoDev SSH. Detecting unrelated system SSH sessions on other computers would require separate authorized access.
- Treat the first-run setup screen as privileged: configure the first administrator promptly after installation. Do not expose the installation or login to the public internet.
- The web terminal in v0.1.1 is intentionally a basic text console, not a full ANSI emulator.
