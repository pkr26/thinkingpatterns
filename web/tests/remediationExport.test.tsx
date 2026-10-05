import { act } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { api, clearSession, setSession } from '../src/api/client';
import * as platform from '../src/platform';
import { vault } from '../src/vault';
import { SettingsView } from '../src/views/Settings';
import { jsonResponse, resetTestState, stubFetch } from './helpers/api';
import { press, render, settle, textOf } from './helpers/rtr';

beforeEach(() => {
  resetTestState();
  setSession('token-A', 'owner-A', 'alice');
  vault.unlock({ authKey: new Uint8Array(32).fill(7), dataKey: new Uint8Array(32).fill(7) }, 'owner-A');
  stubFetch((url) => jsonResponse(url.endsWith('/meta') ? { llm_available: false, audio_available: false } : []));
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('Settings hands a small ticket to native download without fetching or buffering the account body', async () => {
  const issue = vi.spyOn(api, 'exportAccountTicket').mockResolvedValue({ ticket: 'A'.repeat(43), expires_in: 60 });
  const raw = vi.spyOn(api, 'exportAccountRaw');
  const download = vi.spyOn(platform, 'requestAccountDownload').mockReturnValue(true);
  const root = await render(<SettingsView onLockdown={() => undefined} />);
  await settle(10, 4);
  await press(root, 'Download export (encrypted)');
  await settle(10, 3);
  expect(issue).toHaveBeenCalledOnce();
  expect(download).toHaveBeenCalledWith('A'.repeat(43));
  expect(raw).not.toHaveBeenCalled();
  expect(textOf(root)).toContain('Download requested. Check your browser downloads for completion.');
  expect(textOf(root)).not.toContain('Export downloaded');
});

it('retirement between ticket issuance and download handoff cannot start a download', async () => {
  let release!: (value: { ticket: string; expires_in: number }) => void;
  vi.spyOn(api, 'exportAccountTicket').mockImplementation(() => new Promise(resolve => { release = resolve; }));
  const download = vi.spyOn(platform, 'requestAccountDownload').mockReturnValue(true);
  const root = await render(<SettingsView onLockdown={() => undefined} />);
  await settle(10, 4);
  await press(root, 'Download export (encrypted)');
  clearSession(); vault.lock(); await act(async () => root.unmount());
  setSession('token-B', 'owner-B', 'bob');
  vault.unlock({ authKey: new Uint8Array(32), dataKey: new Uint8Array(32) }, 'owner-B');
  await act(async () => release({ ticket: 'A'.repeat(43), expires_in: 60 }));
  expect(download).not.toHaveBeenCalled();
});

it('native download submits only a bounded ticket in a fixed same-origin POST body and releases its form', () => {
  const input: Record<string, unknown> = {};
  const form = { appendChild: vi.fn(), submit: vi.fn(), remove: vi.fn() } as Record<string, any>;
  const createElement = vi.fn((tag: string) => tag === 'form' ? form : input);
  const appendChild = vi.fn();
  vi.stubGlobal('document', { createElement, body: { appendChild } });
  expect(platform.requestAccountDownload('T'.repeat(43))).toBe(true);
  expect(form.action).toBe('/api/v1/account/export-download');
  expect(form.method).toBe('POST');
  expect(form.target).toBe('_self');
  expect(form.enctype).toBe('application/x-www-form-urlencoded');
  expect(input).toEqual({ type: 'hidden', name: 'ticket', value: 'T'.repeat(43) });
  expect(form.submit).toHaveBeenCalledOnce();
  expect(form.remove).toHaveBeenCalledOnce();
  createElement.mockClear();
  expect(platform.requestAccountDownload('T'.repeat(257))).toBe(false);
  expect(platform.requestAccountDownload('x&token=bad')).toBe(false);
  expect(createElement).not.toHaveBeenCalled();
});
