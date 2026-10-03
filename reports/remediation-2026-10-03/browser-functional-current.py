"""Final current-artifact functional check using owned synthetic loopback
fixtures after the recorded security journeys. See README for setup/scope.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
import json
out=Path(__file__).resolve().parent
JOURNAL='Synthetic remediation journal: verified real browser save and history.'
NOTE='Synthetic remediation clinician note: durable navigation and save.'
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless=True)
    for area,url,user,password in [('web','https://127.0.0.1:5195','audit-carol','Remediation-Carol-2026!generation'),('portal','https://127.0.0.1:5196','audit-doc','Remediation-Doc-2026!y')]:
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
            page.screenshot(path=str(out/'web-generation-history-desktop.png'))
            page.set_viewport_size({'width':390,'height':844})
            page.screenshot(path=str(out/'web-generation-history-phone.png'))
        else:
            def open_carol():
                page.locator('.card').filter(has_text='audit-carol').get_by_role('button',name='Open my notes',exact=True).click()
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
            page.screenshot(path=str(out/'portal-final-notes-phone.png'))
        overflow=page.evaluate('document.documentElement.scrollWidth > window.innerWidth')
        assert not overflow, f'{area}: horizontal overflow at phone width'
        assert not errors, errors
        assert not violations, violations
        print(json.dumps({'area':area,'real_crypto_save_and_read':True,'draft_navigation':area=='portal','phone_horizontal_overflow':overflow,'page_errors':errors,'csp_violations':violations}))
        context.close()
    browser.close()
