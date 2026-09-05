/**
 * SettingsScreen: server-URL policy with the explicit insecure-HTTP
 * consent dialog, re-authenticated LLM consent toggle, encrypted export
 * (incl. share-sheet dismissal), and the three-stage destructive delete.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, Share, Switch } from "react-native";

vi.mock("../../src/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock } = await import("../helpers/apiMock");
  return {
    ...actual,
    api: makeApiMock(),
    getBaseUrl: vi.fn(async () => "http://localhost:8000"),
    getInsecureConsentUrl: vi.fn(async () => null),
    setBaseUrl: vi.fn(async () => null),
  };
});

const authKeyB64 = () => authKey.toString("base64");
const verifyPasswordForVault = vi.fn(async () => ({ ok: true as const, verifierB64: authKeyB64() }));
vi.mock("../../src/reauth", () => ({
  verifyPasswordForVault: (...args: unknown[]) => verifyPasswordForVault(...(args as [string])),
}));

vi.mock("../../src/offlineQueue", () => ({
  flushQueue: vi.fn(async () => 0),
  clearQueue: vi.fn(async () => {}),
}));

const signOut = vi.fn(async () => {});
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ signOut }) };
});

const { api, getBaseUrl, getInsecureConsentUrl, setBaseUrl } = await import("../../src/api/client");
const { flushQueue, clearQueue } = await import("../../src/offlineQueue");
const { SettingsScreen } = await import("../../src/screens/SettingsScreen");
const { vault } = await import("../../src/vault");
const {
  render,
  flush,
  textOf,
  pressLabel,
  typeInto,
  pressAlertButton,
  lastAlert,
  touchableByLabel,
  inputByPlaceholder,
} = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

const authKey = Buffer.alloc(32, 2);
const keys = { masterKey: Buffer.alloc(32), authKey, dataKey: Buffer.alloc(32, 3) };
const nav = { popToTop: vi.fn() };

beforeEach(() => {
  resetApi(api as never);
  storage.__reset();
  vi.mocked(clearQueue).mockClear();
  vi.mocked(getBaseUrl).mockReset();
  vi.mocked(getBaseUrl).mockImplementation(async () => "http://localhost:8000");
  vi.mocked(getInsecureConsentUrl).mockReset();
  vi.mocked(getInsecureConsentUrl).mockImplementation(async () => null);
  vi.mocked(setBaseUrl).mockReset();
  vi.mocked(setBaseUrl).mockImplementation(async () => null);
  vi.mocked(flushQueue).mockClear();
  signOut.mockClear();
  nav.popToTop.mockClear();
  Alert.alert.mockClear();
  vi.mocked(Share.share).mockReset();
  vi.mocked(Share.share).mockImplementation(async () => ({}));
  vault.lock();
  vault.unlock({ ...keys });
  verifyPasswordForVault.mockClear();
  verifyPasswordForVault.mockImplementation(async () => ({ ok: true as const, verifierB64: authKeyB64() }));
});

/** Drive the in-screen password re-auth card for a pending action. */
async function reauth(root: Awaited<ReturnType<typeof render>>, password = "correct horse"): Promise<void> {
  await typeInto(root, "password", password);
  await pressLabel(root, "Confirm with password");
  await flush();
}

describe("SettingsScreen chrome", () => {
  it("loads the stored URL, insecure consent and LLM state on mount", async () => {
    vi.mocked(getBaseUrl).mockImplementation(async () => "https://sync.example.com");
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    vi.mocked(api.getLlmConsent).mockResolvedValue({ enabled: true } as never);

    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();

    expect((inputByPlaceholder(root, "https://your-server:8000").props as { value: string }).value).toBe(
      "https://sync.example.com",
    );
    expect(root.root.findAllByType(Switch)).toHaveLength(1);
    const sw = root.root.findAllByType(Switch)[0];
    expect(sw.props.value).toBe(true);
    expect(sw.props.trackColor).toEqual({ true: "#4f7cff", false: "#1a1e26" });
  });

  it("renders an empty, idle form before the stored URL resolves", async () => {
    let resolveUrl!: (v: string) => void;
    vi.mocked(getBaseUrl).mockImplementation(
      () => new Promise((resolve) => (resolveUrl = resolve as (v: string) => void)),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    // First paint: blank URL field, buttons enabled (not busy).
    expect((inputByPlaceholder(root, "https://your-server:8000").props as { value: string }).value).toBe("");
    expect(touchableByLabel(root, "Export my data (encrypted)").props.disabled).toBe(false);
    expect(touchableByLabel(root, "Delete my account and data").props.disabled).toBe(false);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveUrl("http://localhost:8000");
    });
    await flush();
  });

  it("pins the visual language of the screen", async () => {
    const { expectStyle } = await import("../helpers/rtr");
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expectStyle(root, { flex: 1, backgroundColor: "#0f1115", padding: 24, gap: 14 });
    expectStyle(root, { color: "#8a91a3", fontSize: 12, fontWeight: "700", letterSpacing: 1, marginTop: 8 });
    expectStyle(root, { backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 10, padding: 14, fontSize: 15 });
    expectStyle(root, { backgroundColor: "#4f7cff", borderRadius: 10, padding: 16, alignItems: "center" });
    expectStyle(root, { backgroundColor: "#c0392b" }); // danger
    expectStyle(root, { padding: 12, alignItems: "center" }); // ghost
    expectStyle(root, { color: "#8a91a3", fontSize: 14 }); // ghostText
    expectStyle(root, { color: "#fff", fontSize: 16, fontWeight: "600" }); // buttonText
    expectStyle(root, { flexDirection: "row", alignItems: "center", gap: 12, backgroundColor: "#1a1e26", borderRadius: 10, padding: 14 });
    expectStyle(root, { color: "#b6bdc9", fontSize: 13, flex: 1, lineHeight: 18 }); // rowText
    expectStyle(root, { color: "#5c6370", fontSize: 12, textAlign: "center", marginTop: 16, lineHeight: 18 }); // footnote
  });

  it("shows the insecure-HTTP dialog even before stored consent resolves", async () => {
    const { getBaseUrl: gb } = await import("../../src/api/client");
    vi.mocked(gb).mockImplementation(async () => "http://nas.lan:8000");
    let resolveConsent!: (v: string | null) => void;
    vi.mocked(getInsecureConsentUrl).mockImplementation(
      () => new Promise((resolve) => (resolveConsent = resolve as (v: string | null) => void)),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    await pressLabel(root, "Save server URL");
    // Consent is UNKNOWN yet (promise pending) — the warning must still fire.
    expect(lastAlert()[0]).toBe("Insecure server");
    expect(lastAlert()[2]).toEqual([
      { text: "Cancel", style: "cancel" },
      { text: "Allow insecure HTTP", style: "destructive", onPress: expect.any(Function) },
    ]);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveConsent(false);
    });
    await flush();
  });

  it("shows the LLM switch off before the stored consent resolves", async () => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    let resolveConsent!: (v: unknown) => void;
    vi.mocked(api.getLlmConsent).mockImplementation(
      () => new Promise((resolve) => (resolveConsent = resolve)),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(root.root.findAllByType(Switch)[0].props.value).toBe(false);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveConsent({ enabled: true });
    });
    await flush();
    expect(root.root.findAllByType(Switch)[0].props.value).toBe(true);
  });

  it("disables the switch and buttons while the verified consent save is busy, and resets after", async () => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    let resolveSave!: (v: unknown) => void;
    vi.mocked(api.setLlmConsent).mockImplementation(
      () => new Promise((resolve) => (resolveSave = resolve)),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const { act, firePress } = await import("../helpers/rtr");
    const sw0 = root.root.findAllByType(Switch)[0];
    await act(async () => {
      (sw0.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await typeInto(root, "password", "correct horse");
    await firePress(root, "Confirm with password");
    await flush();
    expect(root.root.findAllByType(Switch)[0].props.disabled).toBe(true);
    await act(async () => {
      resolveSave?.({ enabled: true });
    });
    await flush();
    expect(root.root.findAllByType(Switch)[0].props.disabled).toBe(false);

    // busy reset in finally: a second toggle round-trip works.
    vi.mocked(api.setLlmConsent).mockResolvedValue({ enabled: false } as never);
    const sw1 = root.root.findAllByType(Switch)[0];
    await act(async () => {
      (sw1.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(false);
    });
    await flush();
    await reauth(root);
    expect(api.setLlmConsent).toHaveBeenCalledTimes(2);
  });

  it("hides the third-party section when the server has no LLM configured", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(root.root.findAllByType(Switch)).toHaveLength(0);
    expect(textOf(root)).not.toContain("Third-party AI analysis");
  });

  it("keeps defaults when the server is unreachable on mount", async () => {
    vi.mocked(api.meta).mockRejectedValue(new Error("offline"));
    vi.mocked(api.getLlmConsent).mockRejectedValue(new Error("offline"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(root.root.findAllByType(Switch)).toHaveLength(0);
    expect(textOf(root)).toContain("Save server URL");
  });
});

describe("server URL policy", () => {
  it("rejects malformed URLs before saving", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "garbage");
    await pressLabel(root, "Save server URL");
    expect(Alert.alert).toHaveBeenCalledWith("Invalid URL", expect.stringContaining("https://your-server:8000"));
    expect(setBaseUrl).not.toHaveBeenCalled();
  });

  it("demands explicit consent for plain-HTTP servers", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "http://nas.lan:8000");
    await pressLabel(root, "Save server URL");

    expect(setBaseUrl).not.toHaveBeenCalled();
    expect(lastAlert()[0]).toBe("Insecure server");
    const [, message] = lastAlert();
    expect(message).toContain("plain HTTP");
    expect(lastAlert()[2]?.map((b) => b.text)).toEqual(["Cancel", "Allow insecure HTTP"]);

    await pressAlertButton("Cancel");
    expect(setBaseUrl).not.toHaveBeenCalled();

    // H4: consent saves IMMEDIATELY for this exact URL — it can never
    // linger in state to bless a different cleartext server later.
    await pressLabel(root, "Save server URL");
    await pressAlertButton("Allow insecure HTTP");
    expect(setBaseUrl).toHaveBeenCalledWith("http://nas.lan:8000", { allowInsecure: true });
    expect(Alert.alert).toHaveBeenCalledWith("Saved", "Server URL updated (http://nas.lan:8000).");
  });

  it("reports save errors from the consented save", async () => {
    vi.mocked(setBaseUrl).mockImplementation(async () => "Enter a full URL like https://your-server:8000");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "http://nas.lan:8000");
    await pressLabel(root, "Save server URL");
    await pressAlertButton("Allow insecure HTTP");
    expect(Alert.alert).toHaveBeenCalledWith("Could not save server", expect.stringContaining("full URL"));
  });

  it("saves secure URLs without any warning", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "https://api.example.com");
    await pressLabel(root, "Save server URL");
    expect(setBaseUrl).toHaveBeenCalledWith("https://api.example.com", { allowInsecure: false });
    expect(Alert.alert).toHaveBeenCalledWith("Saved", expect.any(String));
  });

  it("saves an insecure URL without the dialog when THIS url was already consented to", async () => {
    vi.mocked(getInsecureConsentUrl).mockImplementation(async () => "http://nas.lan:8000");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "http://nas.lan:8000");
    await pressLabel(root, "Save server URL");
    expect(setBaseUrl).toHaveBeenCalledWith("http://nas.lan:8000", { allowInsecure: true });
    expect(Alert.alert).not.toHaveBeenCalledWith("Insecure server", expect.any(String), expect.anything());
  });

  it("treats empty meta/consent payloads as feature-off", async () => {
    vi.mocked(api.meta).mockResolvedValue({} as never);
    vi.mocked(api.getLlmConsent).mockResolvedValue(undefined as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(root.root.findAllByType(Switch)).toHaveLength(0);
  });
});

describe("LLM consent toggle", () => {
  async function renderWithLlm(): Promise<Awaited<ReturnType<typeof render>>> {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    return root;
  }

  // H2: the toggle alone does nothing — the PASSWORD must be typed and
  // verified against the vault's key before the consent request is sent.
  it("requires the typed password and publishes the server's answer", async () => {
    const root = await renderWithLlm();
    const sw = root.root.findAllByType(Switch)[0];
    expect(sw.props.value).toBe(false);

    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    // Nothing was sent yet: the re-auth card is up, not a network call.
    expect(api.setLlmConsent).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Enter your password to enable");

    await reauth(root);

    expect(verifyPasswordForVault).toHaveBeenCalledWith("correct horse");
    expect(api.setLlmConsent).toHaveBeenCalledWith(true, authKey.toString("base64"));
    expect(root.root.findAllByType(Switch)[0].props.value).toBe(true);
  });

  it("a wrong password never reaches the server", async () => {
    verifyPasswordForVault.mockImplementation(async () => ({ ok: false as const, reason: "wrong-password" as const }));
    const root = await renderWithLlm();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root, "wrong guess");
    expect(api.setLlmConsent).not.toHaveBeenCalled();
    expect(Alert.alert).toHaveBeenCalledWith("Could not verify", "Wrong password.");
    expect(root.root.findAllByType(Switch)[0].props.value).toBe(false);
  });

  it("reports failures and keeps the old state", async () => {
    vi.mocked(api.setLlmConsent).mockRejectedValue(new Error("invalid credentials"));
    const root = await renderWithLlm();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Could not complete", "invalid credentials");
    expect(root.root.findAllByType(Switch)[0].props.value).toBe(false);
  });

  it("falls back to 'unknown error' for non-Error consent failures", async () => {
    vi.mocked(api.setLlmConsent).mockRejectedValue("nope" as never);
    const root = await renderWithLlm();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Could not complete", "unknown error");
  });
});

describe("encrypted export", () => {
  it("flushes the queue, exports and shares the bundle (and can repeat)", async () => {
    vi.mocked(api.exportAccount).mockResolvedValue({ entries: [{}], insights: [{}] } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();

    await pressLabel(root, "Export my data (encrypted)");
    await flush();

    expect(flushQueue).toHaveBeenCalledWith("user-1");
    expect(Share.share).toHaveBeenCalledWith(
      expect.objectContaining({ title: "MindPattern export (encrypted)" }),
    );
    expect(Alert.alert).toHaveBeenCalledWith(
      "Exported",
      "1 entries and 1 insights (encrypted). Keep it safe — it is only decryptable with your password (see tools/decrypt_export.mjs).",
    );

    // busy was reset: a second export works immediately.
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(api.exportAccount).toHaveBeenCalledTimes(2);
  });

  it("skips the flush when no user id is stored, still exports", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(flushQueue).not.toHaveBeenCalled();
    expect(Share.share).toHaveBeenCalledTimes(1);
  });

  // M7: a failed share must never look like a successful export — the
  // old bare catch dismissed EVERY failure (incl. size-limit aborts)
  // without telling the user anything.
  it("a failed share sheet reports 'Export did not complete'", async () => {
    vi.mocked(Share.share).mockRejectedValue(new Error("TransactionTooLarge"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Export did not complete", expect.stringContaining("Nothing left the device"));
  });

  it("a user-dismissed share sheet (dismissedAction) stays quiet", async () => {
    vi.mocked(Share.share).mockResolvedValue({ action: "dismissedAction" } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(Alert.alert).not.toHaveBeenCalledWith(expect.any(String), expect.anything());
  });

  it("refuses oversized exports with an honest message instead of a dead share sheet", async () => {
    const huge = Array.from({ length: 400 }, () => ({ blob: "x".repeat(10_000) }));
    vi.mocked(api.exportAccount).mockResolvedValue({ entries: huge, insights: [] } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Export too large", expect.stringContaining("share sheet"));
    expect(Share.share).not.toHaveBeenCalled();
  });

  it("surfaces export failures", async () => {
    vi.mocked(api.exportAccount).mockRejectedValue(new Error("rate limited"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Export failed", "rate limited");
  });

  it("falls back to 'unknown error' for non-Error export failures", async () => {
    vi.mocked(api.exportAccount).mockRejectedValue("nope" as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Export failed", "unknown error");
  });

  it("keeps working when the pre-export flush itself fails", async () => {
    vi.mocked(flushQueue).mockRejectedValue(new Error("storage corrupted"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(Share.share).toHaveBeenCalledTimes(1);
  });
});

describe("destructive delete", () => {
  it("requires two confirmations and the sign-in key", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");

    expect(lastAlert()[0]).toBe("Delete everything?");
    await pressAlertButton("Cancel");
    expect(api.deleteAccount).not.toHaveBeenCalled();

    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    expect(lastAlert()[0]).toBe("Final confirmation");
    await pressAlertButton("Cancel");
    expect(api.deleteAccount).not.toHaveBeenCalled();

    // H2: the final stage is the PASSWORD PROMPT — nothing is deleted
    // until the typed password re-derives the vault's own key.
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect(api.deleteAccount).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Enter your password to delete everything");
    await reauth(root);

    expect(verifyPasswordForVault).toHaveBeenCalledWith("correct horse");
    expect(api.deleteAccount).toHaveBeenCalledWith(authKey.toString("base64"));
    expect(vault.isUnlocked()).toBe(false);
    expect(signOut).toHaveBeenCalledTimes(1);
  });

  // M11: deletion is the destructive path — everything this account left on
  // the device goes too: queue, mood log, recompute stamp, cached salt.
  it("deletion also wipes the mood log, recompute stamp, cached salt and queue", async () => {
    await storage.setItem("@mindpattern/queue", "[]");
    await storage.setItem("mindpattern.moodlog.user-1", "[{\"date\":\"2026-09-01\",\"value\":0.5}]");
    await storage.setItem("@mindpattern/last_recompute_user-1", "2026-09-04");
    await storage.setItem("@mindpattern/salt_alice", "c2FsdA==");

    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);

    expect(clearQueue).toHaveBeenCalledTimes(1); // the queue wipe itself
    expect(await storage.getItem("mindpattern.moodlog.user-1")).toBeNull();
    expect(await storage.getItem("@mindpattern/last_recompute_user-1")).toBeNull();
    expect(api.clearCachedSalt).toHaveBeenCalledWith("alice");
  });

  it("keeps the session intact when the server refuses, so retry is possible", async () => {
    vi.mocked(api.deleteAccount).mockRejectedValue(new Error("invalid credentials"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);

    expect(Alert.alert).toHaveBeenCalledWith("Delete failed", "invalid credentials");
    expect(signOut).not.toHaveBeenCalled();
  });

  it("falls back to 'unknown error' for non-Error delete failures", async () => {
    vi.mocked(api.deleteAccount).mockRejectedValue("nope" as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Delete failed", "unknown error");
  });

  // H2: a wrong password must never delete anything.
  it("a wrong password blocks the delete entirely", async () => {
    verifyPasswordForVault.mockImplementation(async () => ({ ok: false as const, reason: "wrong-password" as const }));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root, "wrong guess");
    expect(api.deleteAccount).not.toHaveBeenCalled();
    expect(signOut).not.toHaveBeenCalled();
    expect(Alert.alert).toHaveBeenCalledWith("Could not verify", "Wrong password.");
  });

  // M8: the server deletion is irreversible — a LATER local-cleanup failure
  // must not be reported as a failed delete (a retry could never work).
  it("a local cleanup failure after a successful server delete still reports success", async () => {
    vi.mocked(clearQueue).mockRejectedValue(new Error("storage corrupted"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);
    expect(api.deleteAccount).toHaveBeenCalledTimes(1);
    expect(signOut).toHaveBeenCalledTimes(1);
    expect(Alert.alert).toHaveBeenCalledWith("Deleted", expect.stringContaining("deleted from the server"));
    expect(Alert.alert).not.toHaveBeenCalledWith("Delete failed", expect.any(String));
  });
});

describe("sign out", () => {
  it("locks the vault, signs out and pops to the top", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Sign out");
    expect(vault.isUnlocked()).toBe(false);
    expect(signOut).toHaveBeenCalledTimes(1);
    expect(nav.popToTop).toHaveBeenCalledTimes(1);
  });

  // M2: unsynced offline entries must survive sign-out — only deletion wipes.
  it("plain sign-out does NOT clear the offline queue", async () => {
    await storage.setItem("@mindpattern/queue", "[]");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Sign out");
    expect(clearQueue).not.toHaveBeenCalled();
    expect(await storage.getItem("@mindpattern/queue")).toBe("[]");
  });

  it("disables destructive actions while an export is busy", async () => {
    let resolveExport: ((v: unknown) => void) | undefined;
    vi.mocked(api.exportAccount).mockImplementation(
      () => new Promise((resolve) => (resolveExport = resolve)),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const { firePress } = await import("../helpers/rtr");
    await firePress(root, "Export my data (encrypted)");
    expect(touchableByLabel(root, "Delete my account and data").props.disabled).toBe(true);
    expect(touchableByLabel(root, "Export my data (encrypted)").props.disabled).toBe(true);

    const { act } = await import("../helpers/rtr");
    await flush(); // let exportAccount get called and the deferred be created
    await act(async () => {
      resolveExport?.({});
    });
    await flush();
    expect(touchableByLabel(root, "Delete my account and data").props.disabled).toBe(false);
  });
});
