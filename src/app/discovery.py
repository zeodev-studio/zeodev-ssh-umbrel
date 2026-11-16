"""Bounded, authorized SSH discovery of configured private IPv4 networks."""
from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass

MAX_NETWORKS = 4
MAX_TOTAL_HOSTS = 1024
CONCURRENCY = 64

# Only RFC1918 LANs for automatic discovery; other networks can be added as manual hosts.
RFC1918 = tuple(ipaddress.IPv4Network(cidr) for cidr in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'
))


def validate_networks(value: str) -> str:
    """Normalize comma-separated LAN networks and reject overly broad scans."""
    pieces = [item.strip() for item in value.replace('\n', ',').split(',') if item.strip()]
    if len(pieces) > MAX_NETWORKS:
        raise ValueError('Maksymalnie cztery zakresy sieci')
    networks: list[ipaddress.IPv4Network] = []
    for item in pieces:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError(f'Niepoprawny zakres: {item}') from exc
        if not isinstance(net, ipaddress.IPv4Network) or not any(net.subnet_of(lan) for lan in RFC1918):
            raise ValueError('Automatyczne skanowanie działa tylko w prywatnych sieciach IPv4')
        if net.num_addresses > 256:
            raise ValueError('Jeden zakres może obejmować najwyżej 256 adresów (np. /24)')
        if net not in networks:
            networks.append(net)
    unique_ips = {ip for net in networks for ip in net.hosts()}
    if len(unique_ips) > MAX_TOTAL_HOSTS:
        raise ValueError('Zbyt wiele adresów do sprawdzenia')
    return ','.join(str(n) for n in networks)


@dataclass(slots=True)
class ProbeResult:
    address: str
    port: int
    reachable: bool
    banner: str | None = None


async def probe_ssh(address: str, port: int = 22, timeout: float = 0.8) -> ProbeResult:
    """Check SSH banner; do not authenticate or attempt credentials."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=timeout)
        banner_bytes = await asyncio.wait_for(reader.readline(), timeout=timeout)
        banner = banner_bytes.decode('ascii', errors='replace').strip()[:160]
        # RFC 4253 permits server pre-banner text; MVP deliberately accepts only clear SSH banners.
        if banner.startswith('SSH-2.0-') or banner.startswith('SSH-1.99-'):
            return ProbeResult(address, port, True, banner)
        return ProbeResult(address, port, False)
    except (OSError, TimeoutError, asyncio.LimitOverrunError, ValueError):
        return ProbeResult(address, port, False)
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except (OSError, TimeoutError):
                pass


async def scan_networks(value: str) -> tuple[list[str], list[ProbeResult]]:
    normalized = validate_networks(value)
    if not normalized:
        return [], []
    addresses = sorted({str(ip) for chunk in normalized.split(',') for ip in ipaddress.ip_network(chunk).hosts()},
                       key=lambda s: int(ipaddress.ip_address(s)))
    limiter = asyncio.Semaphore(CONCURRENCY)

    async def inspect(address: str) -> ProbeResult:
        async with limiter:
            return await probe_ssh(address, 22)

    results = await asyncio.gather(*(inspect(address) for address in addresses))
    return addresses, [result for result in results if result.reachable]
