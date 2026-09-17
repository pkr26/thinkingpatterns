/**
 * SettingsScreen: server-URL policy (now under "Advanced") with the
 * explicit insecure-HTTP consent dialog, re-authenticated LLM consent
 * toggle, encrypted export (incl. share-sheet dismissal), the three-stage
 * destructive delete, the recovered-entries surface, and the About section.
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
vi.mock("../../src/reauth", async (importOriginal) => {
  // The error classifiers stay REAL: the screen branches 403-vs-401 on them.
  const actual = await importOriginal<typeof import("../../src/reauth")>();
  return {
    ...actual,
    verifyPasswordForVault: (...args: unknown[]) => verifyPasswordForVault(...(args as [string])),
  };
});

vi.mock("../../src/offlineQueue", () => ({
  flushQueue: vi.fn(async () => 0),
  clearQueue: vi.fn(async () => {}),
  rejectedEntryCount: vi.fn(async () => 0),
  requeueRejected: vi.fn(async () => 0),
  quarantinedQueueExists: vi.fn(async () => false),
}));

const signOut = vi.fn(async () => {});
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ signOut }) };
});

const { api, getBaseUrl, getInsecureConsentUrl, setBaseUrl } = await import("../../src/api/client");
const { flushQueue, clearQueue, rejectedEntryCount, requeueRejected, quarantinedQueueExists } = await import(
  "../../src/offlineQueue"
);
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
const nav = { popToTop: vi.fn(), navigate: vi.fn() };

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
  vi.mocked(flushQueue).mockImplementation(async () => 0);
  vi.mocked(rejectedEntryCount).mockReset();
  vi.mocked(rejectedEntryCount).mockImplementation(async () => 0);
  vi.mocked(requeueRejected).mockReset();
  vi.mocked(requeueRejected).mockImplementation(async () => 0);
  vi.mocked(quarantinedQueueExists).mockReset();
  vi.mocked(quarantinedQueueExists).mockImplementation(async () => false);
  signOut.mockClear();
  nav.popToTop.mockClear();
  nav.navigate.mockClear();
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
    const sw = root.root
      .findAllByType(Switch)
      .find((n) => n.props.accessibilityLabel === "Allow third-party AI analysis");
    expect(sw).toBeDefined();
    expect(sw.props.value).toBe(true);
    expect(sw.props.trackColor).toEqual({ true: "#4f7cff", false: "#141821" });
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
    // Design-system pass: theme-composed styles; the footnote moved off the
    // failing #5c6370 onto muted #8a91a3; the button fill is AA-passing.
    const { expectStyle } = await import("../helpers/rtr");
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expectStyle(root, { flex: 1 }); // container base
    expectStyle(root, { backgroundColor: "#0f1115", padding: 24, gap: 14 }); // container themed
    expectStyle(root, { color: "#8a91a3", fontSize: 12, fontWeight: "700", letterSpacing: 1, marginTop: 8 }); // label
    expectStyle(root, { backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 10, padding: 14, fontSize: 15 }); // input
    expectStyle(root, { borderRadius: 10, padding: 16, alignItems: "center", justifyContent: "center" }); // PrimaryButton
    expectStyle(root, { backgroundColor: "#3b5bdb", minHeight: 44 }); // primary fill (AA fix)
    expectStyle(root, { backgroundColor: "#c0392b", minHeight: 44 }); // danger fill
    expectStyle(root, { padding: 12 }); // GhostButton base
    expectStyle(root, { color: "#8a91a3", fontSize: 14 }); // ghostText
    expectStyle(root, { color: "#ffffff", fontSize: 16 }); // buttonText
    expectStyle(root, { flexDirection: "row", alignItems: "center", gap: 12, padding: 14 }); // row base
    expectStyle(root, { backgroundColor: "#1a1e26", borderRadius: 10 }); // row themed
    expectStyle(root, { color: "#b6bdc9", fontSize: 13, flex: 1, lineHeight: 18 }); // rowText
    expectStyle(root, { color: "#8a91a3", fontSize: 12, lineHeight: 18 }); // footnote (contrast fix)
    expectStyle(root, { backgroundColor: "#242a38", borderRadius: 10, minHeight: 44 }); // help surface
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
    expect(root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party AI analysis")!.props.value).toBe(false);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveConsent({ enabled: true });
    });
    await flush();
    expect(root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party AI analysis")!.props.value).toBe(true);
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
    const sw0 = root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party AI analysis")!;
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
    expect(
      root.root.findAllByType(Switch).filter((n) => n.props.accessibilityLabel === "Allow third-party AI analysis"),
    ).toHaveLength(0);
    expect(textOf(root)).not.toContain("Third-party AI analysis");
  });

  it("keeps defaults when the server is unreachable on mount", async () => {
    vi.mocked(api.meta).mockRejectedValue(new Error("offline"));
    vi.mocked(api.getLlmConsent).mockRejectedValue(new Error("offline"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(
      root.root.findAllByType(Switch).filter((n) => n.props.accessibilityLabel === "Allow third-party AI analysis"),
    ).toHaveLength(0);
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

  it("reports save errors from the direct save of a secure URL", async () => {
    vi.mocked(setBaseUrl).mockImplementation(async () => "connection refused");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "https://sync.example.com");
    await pressLabel(root, "Save server URL");
    await flush();
    expect(setBaseUrl).toHaveBeenCalledWith("https://sync.example.com", { allowInsecure: false });
    expect(Alert.alert).toHaveBeenCalledWith("Could not save server", "connection refused");
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
    expect(
      root.root.findAllByType(Switch).filter((n) => n.props.accessibilityLabel === "Allow third-party AI analysis"),
    ).toHaveLength(0);
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
    expect(root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party AI analysis")!.props.value).toBe(true);
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
    expect(root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party AI analysis")!.props.value).toBe(false);
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
    // Calm fallback copy — no raw error text in the dialog (audit fix).
    expect(Alert.alert).toHaveBeenCalledWith("Could not complete", "Something went wrong — try again.");
    expect(root.root.findAllByType(Switch).find((n) => n.props.accessibilityLabel === "Allow third-party AI analysis")!.props.value).toBe(false);
  });

  it("falls back to calm copy for non-Error consent failures", async () => {
    vi.mocked(api.setLlmConsent).mockRejectedValue("nope" as never);
    const root = await renderWithLlm();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Could not complete", "Something went wrong — try again.");
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

  it("surfaces export failures with calm copy (status-mapped for ApiError)", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.exportAccount).mockRejectedValue(new ApiError(429, "rate_limited", "rate_limited", 5_000));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Export failed", "Too many attempts — wait a moment, then try again.");
    // A plain library Error degrades to the fallback sentence, never an echo.
    vi.mocked(api.exportAccount).mockRejectedValue(new Error("rate limited"));
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Export failed", "Something went wrong — try again.");
  });

  it("falls back to calm copy for non-Error export failures", async () => {
    vi.mocked(api.exportAccount).mockRejectedValue("nope" as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Export my data (encrypted)");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Export failed", "Something went wrong — try again.");
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

  it("the crisis-help button navigates to Crisis without any confirmation", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("Confirm with no typed password is a no-op even if the disabled press leaks through", async () => {
    // The native button suppresses this press; the guard inside
    // confirmWithPassword is the second line of defense.
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect(textOf(root)).toContain("Enter your password to delete everything");
    // Password field left empty: the Confirm press must not even attempt re-auth.
    await pressLabel(root, "Confirm with password");
    await flush();
    expect(verifyPasswordForVault).not.toHaveBeenCalled();
    expect(api.deleteAccount).not.toHaveBeenCalled();
    // The card is still up — nothing was cancelled by accident.
    expect(textOf(root)).toContain("Enter your password to delete everything");
  });

  it("Cancel on the password card abandons the pending action", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect(textOf(root)).toContain("Enter your password to delete everything");
    await typeInto(root, "password", "half-typed");
    await pressLabel(root, "Cancel");
    await flush();
    // The pending action and the half-typed password are both discarded.
    expect(textOf(root)).not.toContain("Enter your password to delete everything");
    expect(() => inputByPlaceholder(root, "password")).toThrow();
    expect(verifyPasswordForVault).not.toHaveBeenCalled();
    expect(api.deleteAccount).not.toHaveBeenCalled();
  });

  // M11: deletion is the destructive path — everything this account left on
  // the device goes too: queue, mood log, recompute stamp, cached salt.
  it("deletion also wipes the mood log, recompute stamp, cached salt and queue", async () => {
    await storage.setItem("@mindpattern/queue", "[]");
    await storage.setItem("mindpattern.moodlog.user-1", "[{\"date\":\"2026-09-01\",\"value\":0.5}]");
    await storage.setItem("@mindpattern/last_recompute_user-1", "2026-09-04");
    await storage.setItem("@mindpattern/salt_alice", "c2FsdA==");
    // Per-account acknowledgments die with the account too.
    await storage.setItem("@mindpattern/keyship_consent_user-1", "1");
    await storage.setItem("@mindpattern/onboarding_seen_user-1", "1");

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
    expect(await storage.getItem("@mindpattern/keyship_consent_user-1")).toBeNull();
    expect(await storage.getItem("@mindpattern/onboarding_seen_user-1")).toBeNull();
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

    expect(Alert.alert).toHaveBeenCalledWith("Delete failed", "Something went wrong — try again.");
    expect(signOut).not.toHaveBeenCalled();
  });

  it("falls back to calm copy for non-Error delete failures", async () => {
    vi.mocked(api.deleteAccount).mockRejectedValue("nope" as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Delete failed", "Something went wrong — try again.");
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

describe("verification-failure branching (403 vs 401)", () => {
  it("a 403 on the LLM toggle keeps the card up for a retry (NOT a session death)", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    vi.mocked(api.setLlmConsent).mockRejectedValue(new ApiError(403, "verification_failed", "verification_failed"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("That password didn't match", expect.stringContaining("try again"));
    // The card stays: pending is intact, the password field is cleared.
    expect(textOf(root)).toContain("Enter your password to enable");
    expect((inputByPlaceholder(root, "password").props as { value: string }).value).toBe("");
    expect(signOut).not.toHaveBeenCalled();
  });

  it("a 401 on the LLM toggle reports the dead session (vault already locked by the hook)", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    vi.mocked(api.setLlmConsent).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const sw = root.root.findAllByType(Switch)[0];
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Session expired", "Please unlock again.");
    // The flow concluded — the card is gone (there is nothing to retry here).
    expect(textOf(root)).not.toContain("Enter your password to enable");
  });

  it("a 403 on account deletion keeps the session and offers a retry", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.deleteAccount).mockRejectedValue(new ApiError(403, "verification_failed", "verification_failed"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Delete failed", expect.stringContaining("didn't accept that password"));
    expect(signOut).not.toHaveBeenCalled();
    expect(vault.isUnlocked()).toBe(true);
  });

  it("a 401 on account deletion reports the dead session honestly", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.deleteAccount).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith("Delete failed", expect.stringContaining("Session expired"));
    expect(signOut).not.toHaveBeenCalled();
  });
});

describe("recovered entries surface", () => {
  it("is hidden when the rejected store is empty", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).not.toContain("couldn't sync");
    expect(textOf(root)).not.toContain("Try syncing them again");
  });

  it("offers one-tap recovery when rejected entries exist (requeue + flush)", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(2);
    vi.mocked(requeueRejected).mockResolvedValue(2);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("2 entries couldn't sync and were kept safely on this device.");
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(requeueRejected).toHaveBeenCalledTimes(1);
    expect(flushQueue).toHaveBeenCalledWith("user-1");
    expect(Alert.alert).toHaveBeenCalledWith("Recovered entries", expect.stringContaining("moved back into the sync queue"));
  });

  it("singular wording for a single recovered entry", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(1);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("1 entry couldn't sync and was kept safely on this device.");
  });

  it("reports honestly when nothing could be moved yet", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(1);
    vi.mocked(requeueRejected).mockResolvedValue(0);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Recovered entries", expect.stringContaining("stay safely stored"));
  });

  it("a requeue failure reassures instead of alarming", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(1);
    vi.mocked(requeueRejected).mockRejectedValue(new Error("disk gone"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Could not retry", expect.stringContaining("still safe"));
  });

  it("shows the quarantine notice when a corrupt queue payload was set aside", async () => {
    vi.mocked(quarantinedQueueExists).mockResolvedValue(true);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("damaged piece of the offline queue was set aside instead of deleted");
  });
});

describe("About and Advanced sections", () => {
  it("shows the app version and the honest privacy note", async () => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: false, version: "0.9.1" } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("About");
    expect(textOf(root)).toContain("MindPattern 1.0.0 · server 0.9.1");
    expect(textOf(root)).toContain("encrypted on this device before it leaves");
    expect(textOf(root)).toContain("single-use session");
  });

  it("the privacy policy is one tap from About", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Privacy policy");
    expect(nav.navigate).toHaveBeenCalledWith("Privacy");
  });

  it("the daily-reminder row is honest: no fake control until the native module is linked", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    // 2026-09-17: the native seam copy replaces the old static note; the
    // promise is the same — local-only, optional, honest.
    expect(textOf(root)).toContain("notification module is linked");
    // No reminder switch/button exists (only the haptics + LLM switches).
    const labels = root.root
      .findAllByType(Switch)
      .map((n) => n.props.accessibilityLabel as string);
    expect(labels).not.toContain("Daily reminder");
    expect(labels).toContain("Haptics");
  });

  it("renders the version without the server part when meta has none", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("MindPattern 1.0.0");
    expect(textOf(root)).not.toContain("server undefined");
  });

  it("the developer server-URL setting sits in Advanced, after About", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const texts = (await import("../helpers/rtr")).allText(root);
    const iAbout = texts.findIndex((t) => t === "About");
    const iAdvanced = texts.findIndex((t) => t === "Advanced");
    const iSaveUrl = texts.findIndex((t) => t.includes("Save server URL"));
    expect(iAbout).toBeGreaterThanOrEqual(0);
    expect(iAdvanced).toBeGreaterThan(iAbout);
    expect(iSaveUrl).toBeGreaterThan(iAdvanced);
    // And the consumer actions come first: export precedes About.
    expect(texts.findIndex((t) => t.includes("Export my data"))).toBeLessThan(iAbout);
  });
});

describe("therapist sharing entry point", () => {
  it("navigates to the share screen", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Share with my therapist");
    expect(nav.navigate).toHaveBeenCalledWith("TherapistShare");
  });
});

describe("accessibility", () => {
  it("labels the LLM switch and reports checked/disabled state", async () => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const sw = root.root.findAllByType(Switch)[0];
    expect(sw.props.accessibilityLabel).toBe("Allow third-party AI analysis");
    expect(sw.props.accessibilityState).toEqual({ checked: false, disabled: false });
  });

  it("labels the inputs explicitly", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(inputByPlaceholder(root, "https://your-server:8000").props.accessibilityLabel).toBe("Server URL");
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect(inputByPlaceholder(root, "password").props.accessibilityLabel).toBe("Password confirmation");
  });
});

describe("recovered entries surface — edge branches", () => {
  it("singular moved-count and nothing-left copy", async () => {
    // Mount read → 1; the post-recovery read → 0 left.
    vi.mocked(rejectedEntryCount).mockResolvedValueOnce(1).mockResolvedValue(0);
    vi.mocked(requeueRejected).mockResolvedValue(1);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith(
      "Recovered entries",
      "1 entry moved back into the sync queue — they upload on the next sync.",
    );
  });

  it("some still waiting after the move", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(3);
    vi.mocked(requeueRejected).mockResolvedValue(2);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith(
      "Recovered entries",
      "2 entries moved back into the sync queue — 3 still waiting.",
    );
  });

  it("ignores the recovery tap while another action is busy", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(1);
    let resolveExport: ((v: unknown) => void) | undefined;
    vi.mocked(api.exportAccount).mockImplementation(
      () => new Promise((resolve) => (resolveExport = resolve)),
    );
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const { firePress, act } = await import("../helpers/rtr");
    await firePress(root, "Export my data (encrypted)");
    await flush();
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(requeueRejected).not.toHaveBeenCalled();
    await act(async () => {
      resolveExport?.({});
    });
    await flush();
  });
});
