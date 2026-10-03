"""Final persistent-generation browser preservation check.
Owned synthetic loopback fixtures only. Precondition: audit-carol password
Remediation-Carol-2026!z; changes it to Remediation-Carol-2026!generation.
See README for isolated seed, Chrome/Playwright and HTTPS preview setup.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
import json
out=Path(__file__).resolve().parent
JOURNAL='Synthetic remediation journal: verified real browser save and history.'
NOTE='Synthetic remediation clinician note: durable navigation and save.'
DRAFT='Synthetic unsaved draft preserved through atomic password change.'
PLAN='Synthetic warning signs preserved through atomic password change.'
WEB_OLD='Remediation-Carol-2026!z'; WEB_NEW='Remediation-Carol-2026!generation'; PORTAL_NEW='Remediation-Doc-2026!y'
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless=True)
    context=browser.new_context(viewport={'width':1280,'height':900},ignore_https_errors=True); page=context.new_page();errors=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    def login(user,pw):
        page.locator('input[autocomplete=username]').fill(user)
        page.locator('input[type=password]').fill(pw)
        page.get_by_role('button',name='Sign in',exact=True).click()
        page.get_by_role('heading',name='Sign in',exact=True).wait_for(state='hidden',timeout=60000)
    def nav_more(label):
        page.get_by_role('button',name='More',exact=True).first.click()
        page.get_by_role('menuitem',name=label,exact=True).click()
    page.goto('https://127.0.0.1:5195');login('audit-carol',WEB_OLD)
    for _ in range(2):page.get_by_role('button',name='Next',exact=True).click()
    page.get_by_role('button',name='Start journaling',exact=True).click()
    editor=page.get_by_role('textbox',name='How was today?',exact=True);expect(editor).to_be_enabled();editor.fill(DRAFT)
    nav_more('Safety plan');warning=page.get_by_role('textbox',name='My warning signs',exact=True);warning.fill(PLAN)
    page.get_by_role('button',name='Save my plan',exact=True).click()
    expect(page.locator('body')).to_contain_text('Saved — encrypted on this device',timeout=30000)
    nav_more('Settings');page.get_by_label('New password',exact=True).fill(WEB_NEW)
    page.get_by_label('Confirm new password',exact=True).fill(WEB_NEW)
    page.get_by_role('button',name='Change password',exact=True).click()
    page.get_by_role('heading',name='Sign in',exact=True).wait_for(timeout=60000)
    login('audit-carol',WEB_NEW)
    page.get_by_role('button',name='Today',exact=True).click()
    expect(page.get_by_role('textbox',name='How was today?',exact=True)).to_have_value(DRAFT,timeout=30000)
    nav_more('Safety plan');expect(page.get_by_role('textbox',name='My warning signs',exact=True)).to_have_value(PLAN,timeout=30000)
    page.get_by_role('button',name='History',exact=True).click();page.get_by_label('Search',exact=True).fill(JOURNAL)
    expect(page.locator('body')).to_contain_text(JOURNAL,timeout=30000)
    page.screenshot(path=str(out/'web-after-generation-key-rotation.png'))
    assert not errors, errors
    print(json.dumps({'area':'web','full_v1_atomic_password_and_key_rotation':True,'fresh_login_readable_journal':True,'local_draft_preserved':True,'safety_plan_preserved':True,'page_errors':errors}),flush=True)
    context.close();browser.close()
