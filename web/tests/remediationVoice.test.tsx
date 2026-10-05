import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act } from 'react';
import { EntryView } from '../src/views/Entry';
import { api, clearSession, setSession } from '../src/api/client';
import { loadActiveDraft } from '../src/entryDraft';
import { vault } from '../src/vault';
import { jsonResponse, resetTestState, stubFetch } from './helpers/api';
import { press, pressSwitch, render, settle, typeArea, textOfNode } from './helpers/rtr';

const recorder = vi.hoisted(() => ({ current: {} as Record<string, any> }));
vi.mock('../src/audio/recorder', () => ({ useRecorder: () => recorder.current }));

beforeEach(() => {
  resetTestState();
  setSession('token-A', 'owner-A', 'alice');
  vault.unlock({ authKey: new Uint8Array(32).fill(7), dataKey: new Uint8Array(32).fill(7) }, 'owner-A');
  recorder.current = { state: 'idle', elapsedSeconds: 0, level: 0, recording: null, error: null, start: vi.fn(async () => undefined), stop: vi.fn(), reset: vi.fn() };
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('retired raw audio is never submitted through a replacement account', async () => {
  let release!: (value: ArrayBuffer) => void;
  let reading!: () => void;
  const readStarted = new Promise<void>(resolve => { reading = resolve; });
  const originalAudio = new Uint8Array([91, 25, 73, 99, 51]);
  const blob = new Blob([originalAudio], { type: 'audio/webm' });
  vi.spyOn(blob, 'arrayBuffer').mockImplementation(() => { reading(); return new Promise(resolve => { release = resolve; }); });
  recorder.current.recording = { blob, normalizedMime: 'audio/webm', mime: 'audio/webm', durationSeconds: 5, extension: '.webm' };
  const requests: { url: string; init: RequestInit }[] = [];
  stubFetch((url, init) => { requests.push({ url, init }); return jsonResponse({ original_text: 'Old account audio', language: 'en', language_raw: 'english', english_text: null }); });
  const root = await render(<EntryView onSaved={() => undefined} />);
  await readStarted;
  clearSession(); vault.lock();
  await act(async () => { root.unmount(); });
  setSession('token-B', 'owner-B', 'bob');
  vault.unlock({ authKey: new Uint8Array(32).fill(9), dataKey: new Uint8Array(32).fill(9) }, 'owner-B');
  await act(async () => { release(originalAudio.buffer); });
  await settle(10, 5);
  const posts = requests.filter(row => row.url.endsWith('/audio/transcriptions'));
  expect(posts).toHaveLength(0);
});

it('late transcript preserves newer typing until an explicit insertion choice', async () => {
  let finish!: (response: Response) => void;
  let sent!: () => void;
  const dispatched = new Promise<void>(resolve => { sent = resolve; });
  stubFetch((url) => {
    if (url.endsWith('/audio/transcriptions')) { sent(); return new Promise(resolve => { finish = resolve; }); }
    return jsonResponse({});
  });
  const root = await render(<EntryView onSaved={() => undefined} />);
  await settle(10, 4);
  await typeArea(root, 'How was today?', 'Initial unsaved typed journal');
  recorder.current.recording = { blob: new Blob([new Uint8Array([1, 2, 3])], { type: 'audio/webm' }), normalizedMime: 'audio/webm', mime: 'audio/webm', durationSeconds: 5, extension: '.webm' };
  await act(async () => { root.update(<EntryView onSaved={() => undefined} />); });
  await dispatched;
  const editor = root.root.findAllByType('textarea')[0]!;
  expect(editor.props.disabled).not.toBe(true);
  await typeArea(root, 'How was today?', 'Important new thoughts typed while waiting');
  await act(async () => { finish(jsonResponse({ original_text: 'Only the recorded words', language: 'en', language_raw: 'english', english_text: null })); });
  await settle(10, 5);
  expect(root.root.findAllByType('textarea')[0]!.props.value).toBe('Important new thoughts typed while waiting');
  expect(root.root.findAllByType('button').find(button => button.props.disabled && textOfNode(button).includes('Save entry'))).toBeDefined();
  await press(root, 'Add transcript to draft');
  expect(root.root.findAllByType('textarea')[0]!.props.value).toBe('Important new thoughts typed while waiting\n\nOnly the recorded words');
});

it('stale voice-policy consent cannot acquire the microphone', async () => {
  vi.stubGlobal('MediaRecorder', class MediaRecorder {});
  stubFetch((url) => {
    if (url.endsWith('/meta')) return jsonResponse({ audio_available: true });
    if (url.endsWith('/account/voice-consent')) return jsonResponse({ enabled: true, active_for_current_policy: false });
    return jsonResponse({});
  });
  const root = await render(<EntryView onSaved={() => undefined} />);
  await settle(10, 4);
  await press(root, 'Record instead');
  await settle(10, 3);
  expect(recorder.current.start).not.toHaveBeenCalled();
});

it('current voice-policy consent permits microphone acquisition', async () => {
  vi.stubGlobal('MediaRecorder', class MediaRecorder {});
  stubFetch((url) => jsonResponse(url.endsWith('/meta') ? { audio_available: true } : { enabled: true, active_for_current_policy: true }));
  const root = await render(<EntryView onSaved={() => undefined} />);
  await settle(10, 4);
  await press(root, 'Record instead');
  await settle(10, 3);
  expect(recorder.current.start).toHaveBeenCalledTimes(1);
});

it('finishing a kept-audio upload preserves the newer draft already autosaved during that upload', async () => {
  stubFetch(() => jsonResponse({ original_text: 'Recorded entry to save', language: 'en', language_raw: 'english', english_text: null }));
  const root = await render(<EntryView onSaved={() => undefined} />);
  await settle(10, 4);
  recorder.current.recording = { blob: new Blob([new Uint8Array([1, 2, 3])], { type: 'audio/webm' }), normalizedMime: 'audio/webm', durationSeconds: 5 };
  await act(async () => root.update(<EntryView onSaved={() => undefined} />));
  await settle(10, 5);
  expect(root.root.findAllByType('textarea')[0]!.props.value).toBe('Recorded entry to save');
  await pressSwitch(root);
  vi.spyOn(api, 'createEntry').mockResolvedValue({ id: 'saved-entry' } as Awaited<ReturnType<typeof api.createEntry>>);
  let finish!: () => void, started!: () => void;
  const uploading = new Promise<void>(resolve => { started = resolve; });
  vi.spyOn(api, 'uploadAudioAttachment').mockImplementation(() => { started(); return new Promise(resolve => { finish = () => resolve({} as Awaited<ReturnType<typeof api.uploadAudioAttachment>>); }); });
  await press(root, 'Save entry');
  await uploading;
  await settle(10, 2);
  await typeArea(root, 'How was today?', 'New writing during the audio upload');
  // Wait for the real debounce and real encrypted durable draft write.
  await settle(50, 8);
  expect((await loadActiveDraft(new Uint8Array(32).fill(7), 'owner-A'))?.text).toBe('New writing during the audio upload');
  await act(async () => finish());
  await settle(10, 5);
  expect(root.root.findAllByType('textarea')[0]!.props.value).toBe('New writing during the audio upload');
  expect((await loadActiveDraft(new Uint8Array(32).fill(7), 'owner-A'))?.text).toBe('New writing during the audio upload');
});
