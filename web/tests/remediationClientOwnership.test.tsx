import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act } from 'react';
import { EntryView } from '../src/views/Entry';
import * as patientCrypto from '../src/crypto/patient';
import { clearSession, setSession } from '../src/api/client';
import { QuestionView } from '../src/views/Question';
import { kv } from '../src/kvstore';
import { loadActiveDraft, preserveActiveDraft } from '../src/entryDraft';
import { vault } from '../src/vault';
import { jsonResponse, resetTestState, stubFetch } from './helpers/api';
import { press, render, settle, typeArea } from './helpers/rtr';

beforeEach(() => { resetTestState(); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('retired Entry work cannot send through a replacement session or clear its preserved draft', async () => {
  const keyA = new Uint8Array(32).fill(7), keyB = new Uint8Array(32).fill(9);
  setSession('token-A', 'owner-A', 'alice');
  vault.unlock({ authKey: new Uint8Array(keyA), dataKey: new Uint8Array(keyA) }, 'owner-A');
  const requests: { url: string; init: RequestInit }[] = [];
  stubFetch((url, init) => { requests.push({ url, init }); return jsonResponse({ id: 'created' }, { status: 201 }); });
  let release!: () => void;
  let encrypted!: () => void;
  const reachedEncryption = new Promise<void>(resolve => { encrypted = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  const realEncrypt = patientCrypto.encryptEntry;
  vi.spyOn(patientCrypto, 'encryptEntry').mockImplementation(async (...args) => {
    const result = await realEncrypt(...args);
    encrypted();
    await gate;
    return result;
  });
  const saved = vi.fn();
  const root = await render(<EntryView onSaved={saved} />);
  await settle(10, 3);
  await typeArea(root, 'How was today?', 'Alice confidential journal before account switch');
  await press(root, 'Save entry');
  await reachedEncryption;
  // Reproduce App's teardown: preserve A's draft, end session, zeroize vault, unmount editor.
  const preserved = preserveActiveDraft();
  clearSession(); vault.lock();
  await act(async () => { root.unmount(); });
  await preserved;
  expect((await loadActiveDraft(keyA, 'owner-A'))?.text).toBe('Alice confidential journal before account switch');
  // A different account finishes signing in before A's asynchronous work resolves.
  setSession('token-B', 'owner-B', 'bob');
  vault.unlock({ authKey: new Uint8Array(keyB), dataKey: new Uint8Array(keyB) }, 'owner-B');
  await act(async () => { release(); });
  await settle(20, 8);
  const posts = requests.filter(row => row.url.endsWith('/entries') && row.init.method === 'POST');
  expect(posts).toHaveLength(0);
  expect(saved).not.toHaveBeenCalled();
  expect((await loadActiveDraft(keyA, 'owner-A'))?.text).toBe('Alice confidential journal before account switch');
});

it('retired Question work cannot send the old data key through a replacement session', async () => {
  const keyA = new Uint8Array(32).fill(7);
  setSession('token-A', 'owner-A', 'alice');
  vault.unlock({ authKey: new Uint8Array(keyA), dataKey: new Uint8Array(keyA) }, 'owner-A');
  const requests: { url: string; init: RequestInit }[] = [];
  stubFetch((url, init) => {
    requests.push({ url, init });
    if (url.endsWith('/questions/today')) return jsonResponse({ detail: 'baseline' }, { status: 404 });
    if (url.endsWith('/processing/session')) return jsonResponse({ session_token: 'session-B' });
    return jsonResponse({ detail: 'stop probe after key dispatch' }, { status: 400 });
  });
  let release!: () => void, reached!: () => void;
  const started = new Promise<void>(resolve => { reached = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  const capture = kv.captureWritePermit.bind(kv);
  vi.spyOn(kv, 'captureWritePermit').mockImplementation(async (...args) => { const permit = await capture(...args); reached(); await gate; return permit; });
  const root = await render(<QuestionView onRefreshed={() => undefined} />);
  await settle(10, 3);
  await press(root, 'Refresh patterns');
  await started;
  clearSession(); vault.lock(); await act(async () => { root.unmount(); });
  setSession('token-B', 'owner-B', 'bob');
  vault.unlock({ authKey: new Uint8Array(32).fill(9), dataKey: new Uint8Array(32).fill(9) }, 'owner-B');
  await act(async () => { release(); });
  await settle(10, 5);
  const posted = requests.find(row => row.url.includes('/processing/') && row.init.method === 'POST');
  expect(posted).toBeUndefined();
});


it('retired History edit cannot update or refetch through a replacement account', async () => {
  const { HistoryView } = await import('../src/views/History');
  const keyA = new Uint8Array(32).fill(7);
  setSession('token-A', 'owner-A', 'alice');
  vault.unlock({ authKey: new Uint8Array(keyA), dataKey: new Uint8Array(keyA) }, 'owner-A');
  const { blobB64 } = await patientCrypto.encryptEntry(keyA, 'owner-A', 'entry-A', 'Original private writing', '2026-10-01T12:00:00Z', null, undefined, 1);
  const requests: { url: string; init: RequestInit }[] = [];
  stubFetch((url, init) => {
    requests.push({ url, init });
    if (url.includes('/entries?')) return jsonResponse(url.includes('offset=0') ? [{ id: 'row-A', client_entry_id: 'entry-A', blob: blobB64, entry_date: '2026-10-01', content_version: 1 }] : [], { headers: { 'X-Entries-Revision': '1' } });
    return jsonResponse({});
  });
  const root = await render(<HistoryView />);
  await settle(10, 8);
  await press(root, 'Edit');
  await typeArea(root, 'Your entry', 'Revised private A writing');
  let release!: () => void, reached!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const started = new Promise<void>(resolve => { reached = resolve; });
  const realEncrypt = patientCrypto.encryptEntry;
  vi.spyOn(patientCrypto, 'encryptEntry').mockImplementation(async (...args) => { const result = await realEncrypt(...args); reached(); await gate; return result; });
  await press(root, 'Save edit');
  await started;
  clearSession(); vault.lock(); await act(async () => { root.unmount(); });
  setSession('token-B', 'owner-B', 'bob');
  vault.unlock({ authKey: new Uint8Array(32).fill(9), dataKey: new Uint8Array(32).fill(9) }, 'owner-B');
  const requestsBeforeRetiredCompletion = requests.length;
  await act(async () => { release(); });
  await settle(10, 5);
  expect(requests).toHaveLength(requestsBeforeRetiredCompletion);
  expect(requests.some(row => row.init.method === 'PUT')).toBe(false);
});
