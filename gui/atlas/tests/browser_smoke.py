#!/usr/bin/env python3
"""Ordinary-origin browser qualification; run against contrib/atlas/preview.py.
Uses Playwright supplied by the developer. Does not disable browser policy/CSP.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright
import argparse,json
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--url',default='http://127.0.0.1:8765/');p.add_argument('--browser');p.add_argument('--out',type=Path,required=True);a=p.parse_args()
errors=[];views=[]
with sync_playwright() as p:
 kw={'headless':True}
 if a.browser:kw['executable_path']=a.browser
 browser=p.chromium.launch(**kw);page=browser.new_page(viewport={'width':1440,'height':940});page.on('pageerror',lambda e:errors.append(str(e)))
 page.on('console',lambda m:errors.append(m.text) if any(s in m.text for s in ('Content Security Policy','Refused to load','Refused to connect')) else None)
 page.goto(a.url,wait_until='networkidle');page.locator('#demo-start').click();page.wait_for_timeout(400)
 for view in ['atlas','models','swarms','work','research','economy','compute','mining','wallet','activity','tools','settings']:
  page.locator(f'.nav-item[data-view="{view}"]').click();page.wait_for_timeout(100)
  views.append({'workspace':view,'heading':page.locator('h1').all_text_contents()})
 page.locator('.nav-item[data-view="atlas"]').click();page.wait_for_timeout(300)
 assert page.evaluate('window.atlasDiagnostics.listeners')==1
 diagnostics=page.evaluate('window.atlasDiagnostics');page.screenshot(path=str(a.out.with_suffix('.png')))
 a.out.write_text(json.dumps({'schema':'btx.atlas.browser-smoke/1','browser':browser.version,'errors':errors,'views':views,'diagnostics':diagnostics,'mode':'NORMAL_LOCAL_ORIGIN_CSP_AND_WORKER','native_wallet_tested':False},indent=2))
 browser.close()
 assert not errors,errors
