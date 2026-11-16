# ZeoDev SSH — Umbrel Community App Store

Official ZeoDev Studio community store package for ZeoDev SSH, a self-hosted SSH host discovery and browser terminal app.

The original installation on port 8099 remains separate. This package uses an Umbrel-managed persistent data directory.

Install after the `0.1.1` Docker image is publicly available:
1. Add this repository URL under **Umbrel App Store → Community App Stores**.
2. Install **ZeoDev SSH** from ZeoDev Studio.
3. Configure your administrator password and permitted private LAN discovery networks in the browser.

Source: `src/`. App package: `zeodev-ssh/`. Docker image: `ghcr.io/zeodev-studio/zeodev-ssh-umbrel:0.1.1`.

Do not upload old SSH credentials, .env, or application databases.
