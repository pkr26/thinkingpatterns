"""Actual Chrome journeys against an owned, freshly seeded loopback environment.

Run only with the isolated audit_seed.py synthetic database: the second phase
changes audit-carol/audit-doc passwords and revokes audit-doc sharing grants.
Requires HTTPS built-artifact previews at127.0.0.1:5195 and5196, API at8918,
Playwright and the named macOS Chrome installation. No provider is contacted.
The original fresh seed passwords work once; reset only your disposable
fixture environment before repeating. Screenshots/logs contain synthetic data.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
import json
out=Path(__file__).resolve().parent
JOURNAL='Synthetic remediation journal: verified real browser save and history.'
NOTE='Synthetic remediation clinician note: durable navigation and save.'
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless=True)
    for area,url,user,password in [('web','https://127.0.0.1:5195','audit-carol','audit-carol-2026'),('portal','https://127.0.0.1:5196','audit-doc','Audit-Doc-2026!x')]:
        context=browser.new_context(viewport={'width':1280,'height':900},ignore_https_errors=True)
        page=context.new_page(); errors=[]; violations=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(url)
        page.evaluate("document.addEventListener('securitypolicyviolation', e => console.log('CSP:' + e.violatedDirective))")
        page.on('console',lambda msg:violations.append(msg.text) if msg.text.startswith('CSP:') else None)
        page.locator('input[autocomplete=username]').fill(user)
        page.locator('input[type=password]').fill(password)
        page.get_by_role('button',name='Sign in',exact=True).click()
        page.get_by_role('heading',name='Sign in',exact=True).wait_for(state='hidden',timeout=60000)
        if area=='web':
            for _ in range(2): page.get_by_role('button',name='Next',exact=True).click()
            page.get_by_role('button',name='Start journaling',exact=True).click()
            editor=page.get_by_role('textbox',name='How was today?',exact=True)
            expect(editor).to_be_enabled()
            editor.fill(JOURNAL)
            page.get_by_role('button',name='Save entry',exact=True).click()
            expect(editor).to_have_value('',timeout=30000)
            page.get_by_role('button',name='History',exact=True).click()
            page.get_by_label('Search',exact=True).fill(JOURNAL)
            expect(page.locator('body')).to_contain_text(JOURNAL,timeout=30000)
            page.screenshot(path=str(out/'web-history-desktop.png'))
            page.set_viewport_size({'width':390,'height':844})
            page.screenshot(path=str(out/'web-history-phone.png'))
        else:
            def open_carol():
                page.locator('.card').filter(has_text='audit-carol').get_by_role('button',name='Open patterns',exact=True).click()
                page.get_by_role('textbox',name='New note about this patient',exact=True).wait_for()
            open_carol()
            draft=page.get_by_role('textbox',name='New note about this patient',exact=True)
            expect(draft).to_be_enabled()
            draft.fill(NOTE)
            page.get_by_role('button',name='Back to patients',exact=True).click()
            open_carol()
            draft=page.get_by_role('textbox',name='New note about this patient',exact=True)
            expect(draft).to_have_value(NOTE,timeout=30000)
            page.get_by_role('button',name='Save note',exact=True).click()
            expect(draft).to_have_value('',timeout=30000)
            expect(page.locator('body')).to_contain_text(NOTE,timeout=30000)
            page.get_by_role('button',name='Back to patients',exact=True).click()
            open_carol()
            expect(page.locator('body')).to_contain_text(NOTE,timeout=30000)
            page.set_viewport_size({'width':390,'height':844})
            page.screenshot(path=str(out/'portal-patient-phone.png'))
        overflow=page.evaluate('document.documentElement.scrollWidth > window.innerWidth')
        assert not overflow, f'{area}: horizontal overflow at phone width'
        assert not errors, errors
        assert not violations, violations
        print(json.dumps({'area':area,'real_crypto_save_and_read':True,'draft_navigation':area=='portal','phone_horizontal_overflow':overflow,'page_errors':errors,'csp_violations':violations}))
        context.close()
    browser.close()

from pathlib import Path
from playwright.sync_api import sync_playwright, expect
import json
out=Path(__file__).resolve().parent
JOURNAL='Synthetic remediation journal: verified real browser save and history.'
NOTE='Synthetic remediation clinician note: durable navigation and save.'
DRAFT='Synthetic unsaved draft preserved through atomic password change.'
PLAN='Synthetic warning signs preserved through atomic password change.'
WEB_OLD='audit-carol-2026'; WEB_NEW='Remediation-Carol-2026!x'; PORTAL_NEW='Remediation-Doc-2026!x'
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
    page.screenshot(path=str(out/'web-after-password-change.png'))
    assert not errors, errors
    print(json.dumps({'area':'web','atomic_v1_password_change':True,'fresh_login_readable_journal':True,'local_draft_preserved':True,'safety_plan_preserved':True,'page_errors':errors}),flush=True)
    context.close()
    context=browser.new_context(viewport={'width':1280,'height':900},ignore_https_errors=True);page=context.new_page();errors=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    def open_carol():
        page.locator('.card').filter(has_text='audit-carol').get_by_role('button',name='Open patterns',exact=True).click()
        page.get_by_role('textbox',name='New note about this patient',exact=True).wait_for(timeout=30000)
        expect(page.locator('body')).to_contain_text(NOTE,timeout=30000)
    page.goto('https://127.0.0.1:5196');login('audit-doc','Audit-Doc-2026!x')
    open_carol();page.locator('.entry-row').filter(has_text='First contact — intake summary. Updated:').get_by_role('button',name='View history',exact=True).click()
    expect(page.get_by_role('button',name='Hide history',exact=True)).to_be_visible(timeout=30000)
    expect(page.locator('body')).to_contain_text('First contact — intake summary, presenting concerns.',timeout=30000)
    page.get_by_role('button',name='Back to patients',exact=True).click()
    page.get_by_role('button',name='Show account security',exact=True).click()
    page.get_by_label('Current password',exact=True).fill('Audit-Doc-2026!x')
    page.get_by_label('New password',exact=True).fill(PORTAL_NEW)
    page.get_by_label('Repeat new password',exact=True).fill(PORTAL_NEW)
    page.get_by_role('button',name='Change password',exact=True).click()
    page.get_by_role('heading',name='Sign in',exact=True).wait_for(timeout=60000)
    login('audit-doc',PORTAL_NEW);open_carol()
    page.locator('.entry-row').filter(has_text='First contact — intake summary. Updated:').get_by_role('button',name='View history',exact=True).click()
    expect(page.get_by_role('button',name='Hide history',exact=True)).to_be_visible(timeout=30000)
    expect(page.locator('body')).to_contain_text('First contact — intake summary, presenting concerns.',timeout=30000)
    page.screenshot(path=str(out/'portal-after-password-change.png'))
    page.get_by_role('button',name='Back to patients',exact=True).click()
    page.get_by_role('button',name='Show account security',exact=True).click()
    page.get_by_label('Current password (to authorize rotation)',exact=True).fill(PORTAL_NEW)
    page.get_by_role('checkbox',name='Confirm sharing-key rotation',exact=True).check()
    page.get_by_role('button',name='Rotate sharing key',exact=True).click()
    page.get_by_role('heading',name='Sign in',exact=True).wait_for(timeout=60000)
    login('audit-doc',PORTAL_NEW)
    page.locator('.card').filter(has_text='audit-carol').get_by_role('button',name='Open my notes',exact=True).click()
    expect(page.locator('body')).to_contain_text(NOTE,timeout=30000)
    page.locator('.entry-row').filter(has_text='First contact — intake summary. Updated:').get_by_role('button',name='View history',exact=True).click()
    expect(page.get_by_role('button',name='Hide history',exact=True)).to_be_visible(timeout=30000)
    expect(page.locator('body')).to_contain_text('First contact — intake summary, presenting concerns.',timeout=30000)
    assert not errors,errors
    page.screenshot(path=str(out/'portal-after-sharing-rotation.png'))
    print(json.dumps({'area':'portal','atomic_password_change':True,'fresh_login_current_and_revision_readable':True,'patient_rekey_grant_preserved':True,'sharing_identity_rotation_notes_preserved':True,'page_errors':errors}),flush=True)
    context.close();browser.close()
