import { runTestControl } from "./helpers/testControl";
/** Real session/storage lifecycle for the documented draft retention rules. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import React from "react";
import storage from "./helpers/storageMock";
import { api, setBaseUrl } from "../src/api/client";
import { setSecureStoreBackend } from "../src/secureStore";
import { journalDraftScope, newJournalDraft, saveJournalDraft, loadJournalDraft, waitJournalDraftWrites } from "../src/journalDraft";
import { SessionProvider, useSession, stashDraft, peekStashedJournalDraft } from "../src/store";
import { act, render, flush } from "./helpers/rtr";
import { vault } from "../src/vault";

vi.mock("../src/nativeFeatures", () => ({
  cancelDailyReminder: vi.fn(async () => true),
  cancelMeasureReminder: vi.fn(async () => true),
  cancelOriginNotifications: vi.fn(async () => true),
  migrateOrphanedReminderNotifications: vi.fn(async () => {}),
}));

let session: ReturnType<typeof useSession>;
function Probe() { session = useSession(); return null; }
beforeEach(async () => {
  await waitJournalDraftWrites(); storage.__reset(); runTestControl(setSecureStoreBackend, null); vault.lock();
  vi.spyOn(api, "logout").mockResolvedValue(undefined);
  vi.spyOn(api, "meta").mockResolvedValue({ unlock_days: 30 } as never);
  await setBaseUrl("http://localhost:8000");
});
afterEach(() => { vi.restoreAllMocks(); });

it("sign-out clears the RAM fallback but retains recoverable ciphertext; origin retirement removes both", async () => {
  const user = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key = Buffer.alloc(32, 6);
  await api.setSession("synthetic-test-session", user, "synthetic-user");
  const root = await render(<SessionProvider><Probe /></SessionProvider>);
  try {
    await flush();
    await act(async () => { session.markLoggedIn(); });
    const scope = await journalDraftScope(user);
    const draft = { ...newJournalDraft(), revision: 1, text: "Unsent private words" };
    await saveJournalDraft(key, scope, draft);
    stashDraft(user, draft.text, draft, scope.origin);
    const encrypted = await storage.getItem(scope.slot);
    expect(encrypted).not.toContain(draft.text);

    await act(async () => { await session.signOut(); });
    expect(await api.getUserId()).toBeNull();
    expect(await api.isLoggedIn()).toBe(false);
    expect(peekStashedJournalDraft(user, scope.origin)).toBeNull();
    expect(await storage.getItem(scope.slot)).toBe(encrypted);

    await api.setSession("synthetic-returning-session", user, "synthetic-user");
    await act(async () => { session.markLoggedIn(); });
    expect((await loadJournalDraft(key, scope))?.draft).toEqual(draft);
    stashDraft(user, draft.text, draft, scope.origin);
    await act(async () => { await setBaseUrl("http://localhost:9000"); });
    expect(await storage.getItem(scope.slot)).toBeNull();
    expect(peekStashedJournalDraft(user, scope.origin)).toBeNull();
    expect(await api.getUserId()).toBeNull();
  } finally { await act(async () => { root.unmount(); }); }
});
