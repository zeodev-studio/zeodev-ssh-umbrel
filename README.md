# ZeoDev SSH — Umbrel Community App Store

[![Build and publish](https://github.com/zeodev-studio/zeodev-ssh-umbrel/actions/workflows/publish.yml/badge.svg)](https://github.com/zeodev-studio/zeodev-ssh-umbrel/actions/workflows/publish.yml)

Self-hosted SSH connection manager by **ZeoDev Studio** for Umbrel OS 2.0.

ZeoDev SSH lets you save SSH hosts, discover SSH servers on private networks you administer, check whether a host responds, and open a browser terminal. Passwords and SSH keys are provided at connect time and are not saved in the application's database. A separate login protects the web panel.

## Gallery

![Host dashboard](zeodev-ssh/gallery/1.webp)
![Automatic SSH discovery](zeodev-ssh/gallery/2.webp)
![Network settings](zeodev-ssh/gallery/3.webp)
![First-run setup](zeodev-ssh/gallery/4.webp)

*Gallery captures show the real UI in an empty, unconfigured state; they do not claim a live SSH connection.*

## Native Umbrel installation

1. Confirm that the [GitHub Actions build](https://github.com/zeodev-studio/zeodev-ssh-umbrel/actions/workflows/publish.yml) for version `0.1.2` succeeded.
2. The published GHCR image must be **Public** under GitHub Packages. This is a one-time visibility setting for the package, not for the repository. A public repository alone does **not** make its container packages public.
3. On Umbrel: **App Store → Community App Stores → Add** `https://github.com/zeodev-studio/zeodev-ssh-umbrel`.
4. Open **ZeoDev SSH → Install**. Umbrel then **automatically pulls the published Docker image, starts the container and sets up its app proxy**. You do not need to use `docker compose` or build an image manually on the Umbrel host.
5. Open the app on the Umbrel desktop, create an administrator password, then configure a private scan subnet in Settings.

App ID: `zeodev-ssh` · App port: `8164` · Image: `ghcr.io/zeodev-studio/zeodev-ssh-umbrel:0.1.2`.

**IMPORTANT:** An existing stand-alone `zeodev-ssh` Docker container on port `8099` uses its own `zeodev_ssh_data` volume. Do not delete it or change that volume as part of installing this native app. The native app uses a separate Umbrel-managed data directory.

## Troubleshooting

### App icon appears but opening it fails

Opening an app is not proof that its underlying container is healthy. Check the install state and errors in the Umbrel App Store, then run the following **read-only** diagnostics over SSH on your Umbrel:

```bash
docker ps -a --format 'table {{.Names}}	{{.Image}}	{{.Status}}	{{.Ports}}' | grep -E 'NAMES|zeodev-ssh'
docker image ls 'ghcr.io/zeodev-studio/zeodev-ssh-umbrel'
curl -sS -i --max-time 5 http://127.0.0.1:8164/health || true
```

Check application/proxy logs for containers whose names begin with `zeodev-ssh_`:

```bash
for id in $(docker ps -aq --filter 'name=zeodev-ssh_'); do
  echo "--- $(docker inspect --format '{{.Name}}' "$id") ---"
  docker logs --tail 60 "$id" 2>&1
 done
```

**If the image is missing or the logs mention `401 Unauthorized`**, confirm the GHCR package visibility is Public. **If the image is present but the container exits**, inspect the actual error in the container logs (e.g. permissions for the mapped `/data` folder). **If it works at the LAN address but not over Tailscale**, check the client connection/Tailscale routing instead of rebuilding the container. Do not delete the old port-8099 container while diagnosing.

### Store listing shows an error in the gallery

The manifest includes four real UI screenshots in `zeodev-ssh/gallery` and uses public raw GitHub URLs. Refresh the store or re-add the store after GitHub serves the updated manifest and screenshots.

## For maintainers

- `src/`: FastAPI, SQLite, SSH connection logic, static responsive UI and tests
- `zeodev-ssh/`: Umbrel package manifest, Docker Compose and actual gallery screenshots
- `.github/workflows/publish.yml`: validates tests and release version, then builds and publishes both AMD64 and ARM64 images to GHCR

Run tests: `cd src && python -m pytest tests -q`.

Release procedure: bump the image tag, manifest version and Actions tag together. Confirm the registry image is publicly pullable before updating Umbrel. Never publish `.env`, credentials, SSH private keys or databases.