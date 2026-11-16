import pytest
from fastapi.testclient import TestClient
from app import main, store, discovery

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store,'DATA_DIR',tmp_path)
    monkeypatch.setattr(store,'DB_FILE',tmp_path/'test.sqlite3')
    monkeypatch.setattr(store,'KEY_FILE',tmp_path/'session.key')
    monkeypatch.setenv('ZEODEV_ADMIN_PASSWORD','a-test-long-initial-password')
    monkeypatch.delenv('ZEODEV_SCAN_CIDRS',raising=False)
    with TestClient(main.app, base_url='http://testserver') as client:
        yield client

def post(c, url, json=None, method='POST'):
    return c.request(method,url,json=json,headers={'Origin':'http://testserver'})

def test_requires_admin_login(client):
    assert client.get('/health').json()['status']=='ok'
    assert client.get('/api/hosts').status_code == 401
    assert client.get('/api/discovery').status_code == 401
    assert client.get('/api/status').status_code == 401
    assert post(client,'/api/login',{'password':'wrong'}).status_code == 401
    assert post(client,'/api/login',{'password':'a-test-long-initial-password'}).status_code==200
    assert client.get('/api/hosts').json()=={'hosts':[]}
    assert post(client,'/api/logout').status_code==200
    assert client.get('/api/hosts').status_code==401

def test_csrf_denies_missing_origin(client):
    assert client.post('/api/login',json={'password':'a-test-long-initial-password'}).status_code==403
    assert post(client,'/api/login',{'password':'a-test-long-initial-password'}).status_code==200
    assert client.post('/api/hosts',json={'name':'A','address':'192.168.1.10','username':'root'}).status_code==403

def test_host_crud_and_validation(client):
    post(client,'/api/login',{'password':'a-test-long-initial-password'})
    payload={'name':'Mini PC','address':'192.168.1.13','port':22,'username':'user'}
    r=post(client,'/api/hosts',payload)
    assert r.status_code==201
    host=r.json()
    assert host['name']=='Mini PC'
    assert 'password' not in host
    assert post(client,'/api/hosts',{**payload,'address':'http://evil.test'}).status_code==422
    r=post(client,'/api/hosts/'+host['id'],{**payload,'name':'New name'},method='PUT')
    assert r.json()['name']=='New name'
    assert post(client,'/api/hosts/'+host['id'],method='DELETE').json()['ok']
    assert client.get('/api/hosts').json()['hosts']==[]

def test_scan_api(client,monkeypatch):
    post(client,'/api/login',{'password':'a-test-long-initial-password'})
    r=post(client,'/api/discovery/settings',{'cidrs':'192.168.1.4/32'},method='PUT')
    assert r.status_code==200
    assert r.json()['cidrs']=='192.168.1.4/32'
    assert post(client,'/api/discovery/settings',{'cidrs':'1.1.1.0/24'},method='PUT').status_code==422
    async def fake_scan(value):
        assert value=='192.168.1.4/32'
        return ['192.168.1.4'],[discovery.ProbeResult('192.168.1.4',22,True,'SSH-2.0-OpenSSH')]
    monkeypatch.setattr(discovery,'scan_networks',fake_scan)
    assert post(client,'/api/discovery/scan').json()['found']==1
    d=client.get('/api/discovery').json()
    assert len(d['devices'])==1
    assert d['devices'][0]['address']=='192.168.1.4'
    assert d['devices'][0]['reachable']

def test_change_password(client):
    post(client,'/api/login',{'password':'a-test-long-initial-password'})
    r=post(client,'/api/change-password',{'currentPassword':'bad','newPassword':'replacement-password-12345'})
    assert r.status_code==403
    r=post(client,'/api/change-password',{'currentPassword':'a-test-long-initial-password','newPassword':'replacement-password-12345'})
    assert r.status_code==200
    post(client,'/api/logout')
    assert post(client,'/api/login',{'password':'a-test-long-initial-password'}).status_code==401
    assert post(client,'/api/login',{'password':'replacement-password-12345'}).status_code==200

def test_static_and_no_agent_endpoints(client):
    assert client.get('/').status_code==200
    assert 'ZeoDev SSH' in client.get('/').text
    assert client.get('/static/app.js').status_code==200
    assert client.get('/manifest.webmanifest').status_code==200
    assert client.get('/api/agent/hosts').status_code==404

def test_native_umbrel_first_run_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA_DIR', tmp_path)
    monkeypatch.setattr(store, 'DB_FILE', tmp_path/'test.sqlite3')
    monkeypatch.setattr(store, 'KEY_FILE', tmp_path/'session.key')
    monkeypatch.delenv('ZEODEV_ADMIN_PASSWORD', raising=False)
    monkeypatch.setenv('ZEODEV_ALLOW_WEB_SETUP', 'true')
    monkeypatch.delenv('ZEODEV_SCAN_CIDRS', raising=False)
    with TestClient(main.app, base_url='http://testserver') as c:
        assert c.get('/api/setup').json() == {'needsSetup': True, 'authenticated': False}
        assert c.post('/api/initialize', json={'password':'some-long-admin-password'}).status_code == 403
        assert post(c, '/api/initialize', {'password':'short'}).status_code == 422
        assert post(c, '/api/initialize', {'password':'some-long-admin-password'}).status_code == 200
        assert c.get('/api/setup').json() == {'needsSetup': False, 'authenticated': True}
        assert post(c, '/api/initialize', {'password':'a-different-new-password'}).status_code == 409
        assert c.get('/api/hosts').json() == {'hosts':[]}
    # Persist admin across process restarts without the bootstrap secret.
    with TestClient(main.app, base_url='http://testserver') as c:
        assert c.get('/api/setup').json() == {'needsSetup': False, 'authenticated': False}
        assert post(c, '/api/login', {'password':'some-long-admin-password'}).status_code == 200


def test_native_setup_is_disabled_in_standalone(tmp_path, monkeypatch):
    monkeypatch.setattr(store,'DATA_DIR',tmp_path)
    monkeypatch.setattr(store,'DB_FILE',tmp_path/'test.sqlite3')
    monkeypatch.setattr(store,'KEY_FILE',tmp_path/'session.key')
    monkeypatch.setenv('ZEODEV_ADMIN_PASSWORD','a-test-long-initial-password')
    monkeypatch.delenv('ZEODEV_ALLOW_WEB_SETUP', raising=False)
    monkeypatch.delenv('ZEODEV_SCAN_CIDRS', raising=False)
    with TestClient(main.app, base_url='http://testserver') as c:
        assert post(c, '/api/initialize', {'password':'some-long-admin-password'}).status_code == 403
