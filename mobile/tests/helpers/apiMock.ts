/**
 * Shared shape for the mocked api client used by component/store tests.
 * Each test file gets a fresh instance via vi.mock factories importing
 * makeApiMock(); individual methods are re-stubbed per test with
 * vi.mocked(api.x).mockResolvedValue(...) / mockRejectedValue(...).
 *
 * ApiError mirrors the real class (name included) because screens branch on
 * `err instanceof ApiError` and on err.status.
 */
import { vi, type Mock } from "vitest";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
    public retryAfterMs?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export const SALT_B64 = Buffer.alloc(16, 7).toString("base64");
export const ENTRY_PAGE_BYTES = 2 * 1024 * 1024;

export function makeApiMock() {
  const listEntries = vi.fn(async () => []);
  return {
    meta: vi.fn(async () => ({ unlock_days: 30, llm_available: false, sharing_available: true })),
    isLoggedIn: vi.fn(async () => false),
    getUserId: vi.fn(async () => "user-1"),
    getUsername: vi.fn(async () => "alice"),
    setSession: vi.fn(async () => {}),
    clearSession: vi.fn(async () => {}),
    register: vi.fn(async () => ({ token: "tok", user_id: "user-1" })),
    saltFor: vi.fn(async () => ({ salt: SALT_B64 })),
  cacheSalt: vi.fn(async () => {}),
  getCachedSalt: vi.fn(async () => null),
  clearCachedSalt: vi.fn(async () => {}),
    login: vi.fn(async () => ({ token: "tok", user_id: "user-1" })),
    logout: vi.fn(async () => ({})),
    createEntry: vi.fn(async () => ({})),
    createQueuedEntry: vi.fn(async () => ({})),
    updateEntry: vi.fn(async () => ({})),
    // Keep older screen tests that seed listEntries meaningful while the
    // production client consumes bounded pages.
    listEntriesPage: vi.fn(async () => ({ entries: await listEntries(), nextOffset: null, revision: null })),
    listEntries,
    deleteEntry: vi.fn(async () => ({})),
    insights: vi.fn(async () => ({ phase: "baseline", active_days: 0, days_remaining: 30 })),
    questionToday: vi.fn(async () => ({ for_date: "2026-09-03", blob: "" })),
    openProcessingSession: vi.fn(async () => ({ session_token: "st" })),
    recompute: vi.fn(async () => ({ question_stored: true })),
    exportAccount: vi.fn(async () => ({ entries: [], insights: [] })),
    deleteAccount: vi.fn(async () => ({})),
    getLlmConsent: vi.fn(async () => ({ enabled: false })),
    setLlmConsent: vi.fn(async () => ({ enabled: true })),
    // Therapist sharing (2026-09-16)
    pairingLookup: vi.fn(async () => ({
      therapist_id: "therapist-1",
      display_name: "Dr. Mock",
      wrap_pub_key: "A".repeat(124),
    })),
    grantConsent: vi.fn(async () => ({
      id: "a".repeat(32),
      therapist_id: "therapist-1",
      display_name: "Dr. Mock",
      username: "drmock",
      status: "active",
      granted_at: "2026-09-16T12:00:00Z",
      revoked_at: null,
    })),
    listConsents: vi.fn(async () => []),
    revokeConsent: vi.fn(async () => ({})),
  };
}

/** Reset every method to its default implementation (vi.resetAllMocks
 *  alone would leave them returning undefined). */
export function resetApi(api: ReturnType<typeof makeApiMock>): void {
  const defaults = makeApiMock();
  for (const key of Object.keys(defaults) as (keyof typeof api)[]) {
    const mock = api[key] as unknown as Mock;
    mock.mockReset();
    // Legacy component fixtures seed `listEntries`; preserve that ergonomic
    // seam while production screens request bounded pages.
    if (key === "listEntriesPage") {
      mock.mockImplementation(async () => ({
        entries: await (api.listEntries as unknown as () => Promise<unknown>)(),
        nextOffset: null,
        revision: null,
      }));
    } else {
      mock.mockImplementation(defaults[key] as (...args: unknown[]) => unknown);
    }
  }
}
