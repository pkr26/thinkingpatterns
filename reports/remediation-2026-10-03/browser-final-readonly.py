"""Read-only current-artifact check after the exact recorded synthetic journey.
Requires owned loopback seed fixtures and post-journey synthetic credentials;
see README. This is the executed probe, not a general deployment test.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
import json
root=Path(__file__).resolve().parent
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless=True)
 for area,url,user,pw in [('web','https://127.0.0.1:5195','audit-carol','Remediation-Carol-2026!generation'),('portal','https://127.0.0.1:5196','audit-doc','Remediation-Doc-2026!y')]:
  context=browser.new_context(ignore_https_errors=True,viewport={'width':390,'height':844});page=context.new_page();errors=[]
  page.on('pageerror',lambda error:errors.append(str(error)))
  page.goto(url);page.locator('input[autocomplete=username]').fill(user);page.locator('input[type=password]').fill(pw)
  page.get_by_role('button',name='Sign in',exact=True).click();page.get_by_role('heading',name='Sign in',exact=True).wait_for(state='hidden',timeout=60000)
  if area=='web':
   for _ in range(2):page.get_by_role('button',name='Next',exact=True).click()
   page.get_by_role('button',name='Start journaling',exact=True).click();page.get_by_role('button',name='History',exact=True).click()
   page.get_by_label('Search',exact=True).fill('Synthetic remediation journal: verified real browser save and history.')
   expect(page.locator('body')).to_contain_text('Synthetic remediation journal: verified real browser save and history.',timeout=30000)
  else:
   page.locator('.card').filter(has_text='audit-carol').get_by_role('button',name='Open my notes',exact=True).click()
   expect(page.locator('body')).to_contain_text('Synthetic remediation clinician note: durable navigation and save.',timeout=30000)
   expect(page.get_by_role('button',name='View history',exact=True)).to_have_count(1)
   page.locator('.entry-row').filter(has_text='First contact — intake summary. Updated:').get_by_role('button',name='View history',exact=True).click()
   expect(page.locator('body')).to_contain_text('First contact — intake summary, presenting concerns.',timeout=30000)
   assert 'earlier versions could not be decrypted' not in page.locator('body').inner_text()
  assert not page.evaluate('document.documentElement.scrollWidth>window.innerWidth')
  assert not errors,errors
  page.screenshot(path=str(root/f'{area}-final-phone.png'))
  print(json.dumps({'area':area,'current_artifact_fresh_login_and_history':True,'real_historical_revision':area=='portal','new_note_history_marker_absent':area=='portal','phone_reflow':True,'page_errors':errors}),flush=True)
  context.close()
 browser.close()
