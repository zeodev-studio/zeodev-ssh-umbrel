import asyncio
import pytest
from app.discovery import validate_networks, scan_networks, probe_ssh

@pytest.mark.parametrize('cidr', ['0.0.0.0/0','8.8.8.0/24','127.0.0.0/24','192.168.0.0/16','2001:db8::/120','100.64.0.0/24'])
def test_reject_unsafe_scan_ranges(cidr):
    with pytest.raises(ValueError):
        validate_networks(cidr)

def test_normalize_private_subnets():
    assert validate_networks('192.168.1.4/24, 10.2.3.0/29') == '192.168.1.0/24,10.2.3.0/29'
    assert validate_networks('') == ''

@pytest.mark.asyncio
async def test_probe_ssh_banner():
    async def serve(_reader, writer):
        writer.write(b'SSH-2.0-TestServer\r\n'); await writer.drain();await asyncio.sleep(.02);writer.close()
    server = await asyncio.start_server(serve, '127.0.0.1', 0)
    try:
        port = server.sockets[0].getsockname()[1]
        result = await probe_ssh('127.0.0.1', port)
        assert result.reachable
        assert result.banner.startswith('SSH-2.0-')
    finally:
        server.close();await server.wait_closed()

@pytest.mark.asyncio
async def test_reject_non_ssh_banner():
    async def serve(_reader, writer):
        writer.write(b'HTTP/1.1 200 OK\r\n'); await writer.drain(); writer.close()
    server = await asyncio.start_server(serve,'127.0.0.1',0)
    try:
        result = await probe_ssh('127.0.0.1',server.sockets[0].getsockname()[1]);assert not result.reachable
    finally:
        server.close();await server.wait_closed()
