from playwright.sync_api import sync_playwright
from pathlib import Path
from PIL import Image
import base64, shutil
root=Path(__file__).resolve().parents[1]
html=(root/'src/app/static/index.html').read_text()
css=(root/'src/app/static/style.css').read_text()
logo=(root/'src/app/static/icon.svg').read_text()
logo_uri='data:image/svg+xml;base64,'+base64.b64encode(logo.encode()).decode()
html=html.replace('src="/static/icon.svg"',f'src="{logo_uri}"')
html=html.replace('<link rel="stylesheet" href="/static/style.css">','<style>'+css+'</style>')
html=html.replace('<script src="/static/app.js" defer></script>','')
out=root/'zeodev-ssh/gallery';out.mkdir(exist_ok=True)
with sync_playwright() as p:
    b=p.chromium.launch(headless=True,executable_path=shutil.which('chromium') or None,args=['--no-sandbox','--disable-dev-shm-usage'])
    page=b.new_page(viewport={'width':1440,'height':810},device_scale_factor=1)
    page.set_content(html,wait_until='load')
    page.evaluate("""() => { document.getElementById('app-shell').hidden=false; document.getElementById('setup-screen').hidden=true; document.getElementById('login-screen').hidden=true; document.getElementById('stat-hosts').textContent='0';document.getElementById('stat-online').textContent='0';document.getElementById('stat-sessions').textContent='0';document.getElementById('host-list').innerHTML='<div class=empty-state><div class=empty-symbol>⌁</div><strong>Nie masz jeszcze żadnego urządzenia</strong><p>Wybierz „Dodaj SSH” lub znajdź serwer automatycznie w zakładce Wykryte SSH.</p></div>'; }""")
    shots=[('devices','devices'),('discovery','discovery'),('settings','settings')]
    for index,(name,selector) in enumerate(shots,start=1):
        page.evaluate("""selector => { document.querySelectorAll('[data-page]').forEach(x=>x.hidden=x.dataset.page!==selector);document.querySelectorAll('[data-view]').forEach(x=>x.classList.toggle('active',x.dataset.view===selector));document.getElementById('breadcrumb').textContent=({'devices':'Urządzenia','discovery':'Wykryte SSH','settings':'Ustawienia'})[selector]; if(selector==='discovery')document.getElementById('discovered-list').innerHTML='<div class=empty-state><div class=empty-symbol>⌁</div><strong>Nic jeszcze nie wykryto</strong><p>Sprawdź ustawienia sieci oraz czy serwery SSH mają włączoną usługę na porcie 22.</p></div>'; }""", selector)
        path=out/f'{index}.webp'
        page.screenshot(path='/tmp/zeodev-tmp.png')
        Image.open('/tmp/zeodev-tmp.png').convert('RGB').save(path,'WEBP',quality=86,method=6)
        print(name,path.stat().st_size)
    page.evaluate("""() => { document.getElementById('app-shell').hidden=true;document.getElementById('setup-screen').hidden=false;}""")
    path=out/'4.webp';page.screenshot(path='/tmp/zeodev-tmp.png');Image.open('/tmp/zeodev-tmp.png').convert('RGB').save(path,'WEBP',quality=86,method=6)
    print('setup',path.stat().st_size)
    b.close()
