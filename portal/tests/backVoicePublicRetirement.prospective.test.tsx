import { expect, it } from "vitest";
import { openNativeChart } from "./helpers/prospectiveNativeChart";

it("revokes the authenticated native recording URL when public Back removes evidence audio", async () => {
  const chart = await openNativeChart();
  try {
    await chart.evidence(); await chart.press("play recording"); await chart.audioVisible();
    const audio = chart.root().root.findByType("audio"), url = String(audio.props.src);
    expect(chart.urls.get(url)?.digest).toBe(chart.account.audioDigest);
    await chart.press("Back to all patterns");
    expect(chart.root().root.findAllByType("audio")).toHaveLength(0);
    expect(chart.urls.get(url)?.active).toBe(false);
    expect(chart.text()).toContain("See the evidence");
    chart.clean();
  } finally { await chart.retire(); }
  // Two current Retry schedules share this original body. Every interaction
  // looks up the current public control; only genuine owned HTTP replies wait.
  for (const phase of ["before-refetch", "failed-refetch"] as const) {
    const retiredEdit = await openNativeChart({ retiredEditConflict: phase });
    try {
      expect(retiredEdit.text()).toContain("Retry loading this patient");
      await retiredEdit.editTarget(); await retiredEdit.press("Save edit");
      await retiredEdit.retiredEditArrives();
      await retiredEdit.press("Retry loading this patient"); await retiredEdit.currentRetryLoaded();
      const currentEditor = retiredEdit.root().root.findAllByType("textarea").find(node => node.props.placeholder === "Editing note…");
      expect(currentEditor?.props.value).toBe("My preserved authenticated edit");
      expect(retiredEdit.root().root.findAllByType("button").some(node => node.children.join("") === "Saving…" && node.props.disabled === true)).toBe(true);
      await retiredEdit.finishRetiredEdit();
      expect(retiredEdit.text()).toContain("See the evidence");
      expect(retiredEdit.root().root.findAllByType("textarea").find(node => node.props.placeholder === "Editing note…")?.props.value).toBe("My preserved authenticated edit");
      if (phase === "before-refetch") {
        expect(retiredEdit.retiredEditNoteDispatches(), "a retired edit cannot admit another protected notes GET after current Retry").toEqual([]);
      } else {
        expect(retiredEdit.text(), "an obsolete conflict refetch must not replace the current chart with its warning").not.toContain("This note changed on another device. Your draft is preserved, but the current saved version could not be loaded. Retry when connected.");
      }
      retiredEdit.clean();
    } finally { await retiredEdit.retire(); }
  }
  // Let a real old initial notes load reach authenticated decryption before
  // public Retry loads a distinct newer snapshot. A public React Profiler owns
  // every commit; neither crypto results nor completion order are altered.
  {
    const initialNotes = await openNativeChart({ retiredInitialNotesDecrypt: true });
    try {
      await initialNotes.notesFirstPageArrives();
      await initialNotes.finishInitialNotesThroughCurrentRetry();
      expect(initialNotes.initialNoteCommitTexts().filter(text => text.includes("Original authenticated note")), "A retired initial notes load cannot publish its obsolete plaintext in any committed App view after current Retry").toEqual([]);
      expect(initialNotes.initialNoteCommitTexts().some(text => text.includes("Colleague authenticated winning note")), "The public Profiler must observe the authenticated current Retry note commit").toBe(true);
      initialNotes.clean();
    } finally { await initialNotes.retire(); }
  }
  // A terminal single-page notes response has no next traversal guard.
  // Retire it through current Retry before its genuine HTTP response completes.
  {
    const terminalNotes = await openNativeChart({ retiredSinglePageNotes: true });
    try {
      await terminalNotes.notesFirstPageArrives();
      await terminalNotes.press("Retry loading this patient");
      await terminalNotes.completed("replacement winning note and healthy chart commit", () => terminalNotes.text().includes("Colleague authenticated winning note") && terminalNotes.text().includes("See the evidence") && !terminalNotes.text().includes("Retry loading this patient"));
      expect(terminalNotes.noteDecryptAdmissions(terminalNotes.account.winning.blob), "Current winning note uses its real original exported decrypt Promise").toHaveLength(1);
      await terminalNotes.finishRetiredTerminalNotes();
      expect(terminalNotes.noteDecryptAdmissions(terminalNotes.account.target.blob), "A retired terminal notes response cannot admit decryption of its obsolete authenticated note").toHaveLength(0);
      expect(terminalNotes.text()).toContain("Colleague authenticated winning note");
      terminalNotes.clean();
    } finally { await terminalNotes.retire(); }
  }
  // A nonempty, independently sealed measure makes the obsolete-load
  // admission guard observable without replacing any crypto producer.
  {
    const retiredMeasures = await openNativeChart({ retiredMeasures: true });
    try {
      await retiredMeasures.measuresFirstPageArrives();
      await retiredMeasures.press("Retry loading this patient");
      await retiredMeasures.completed("current replacement chart commits without the held old measure", () => retiredMeasures.text().includes("Original authenticated note") && retiredMeasures.text().includes("See the evidence") && !retiredMeasures.text().includes("Retry loading this patient"));
      await retiredMeasures.finishRetiredMeasures();
      expect(retiredMeasures.measureDecryptAdmissions(retiredMeasures.account.measure!.blob), "A retired nonempty measures response cannot admit its original authenticated measure decryption").toHaveLength(0);
      expect(retiredMeasures.text()).not.toContain("Recorded measures (1)");
      retiredMeasures.clean();
    } finally { await retiredMeasures.retire(); }
    const healthyMeasures = await openNativeChart({ nativeMeasures: true });
    try {
      await healthyMeasures.completed("healthy genuine measure publicly displays", () => healthyMeasures.text().includes("Recorded measures (1)"));
      expect(healthyMeasures.measureDecryptAdmissions(healthyMeasures.account.measure!.blob), "Healthy public measures admit the same independently sealed measure through its original decrypt Promise").toHaveLength(1);
      expect(healthyMeasures.text()).toContain("2026-10-01: 2");
      healthyMeasures.clean();
    } finally { await healthyMeasures.retire(); }
  }
  // A successful original conflict-note decrypt retires through the current
  // public Retry before the old caller can publish its comparison warning.
  // Preserve every public commit; the two genuine loads may finish in either order.
  {
    const latestConflict = await openNativeChart({ retiredEditConflict: "after-latest-decrypt" });
    try {
      expect(latestConflict.text()).toContain("Retry loading this patient");
      await latestConflict.editTarget(); await latestConflict.press("Save edit");
      await latestConflict.finishLatestConflictDecryptThroughCurrentRetry();
      expect(latestConflict.latestConflictCommitTexts().filter(text => text.includes("This note changed on another device. Your draft is preserved. Compare the current saved text below before retrying your edit.")), "An obsolete successful conflict decrypt cannot publish its comparison warning in any committed App view after current Retry").toEqual([]);
      expect(latestConflict.latestConflictCommitTexts().some(text => text.includes("Colleague authenticated winning note") && text.includes("See the evidence") && !text.includes("Retry loading this patient")), "The public Profiler must observe the genuine current Retry chart commit").toBe(true);
      expect(latestConflict.noteDecryptAdmissions(latestConflict.account.winning.blob), "Both the old conflict and current Retry use identical genuine exported decrypt Promises").toHaveLength(2);
      expect(latestConflict.root().root.findAllByType("textarea").find(node => node.props.placeholder === "Editing note…")?.props.value).toBe("My preserved authenticated edit");
      latestConflict.clean();
    } finally { await latestConflict.retire(); }
  }
  // The old terminal-empty409 refetch passes its own API-await guard before
  // one causally queued public Retry retires it during the outer await graph.
  {
    const terminalConflict = await openNativeChart({ retiredEditConflict: "after-terminal-refetch" });
    try {
      expect(terminalConflict.text()).toContain("Retry loading this patient");
      await terminalConflict.editTarget(); await terminalConflict.press("Save edit");
      await terminalConflict.finishTerminalConflictThroughCurrentRetry();
      expect(terminalConflict.latestConflictCommitTexts().filter(text => text.includes("This note changed on another device. Your draft is preserved. Compare the current saved text below before retrying your edit.")), "An obsolete terminal conflict result cannot publish its comparison warning in any committed App view after current Retry").toEqual([]);
      expect(terminalConflict.latestConflictCommitTexts().some(text => text.includes("Colleague authenticated winning note") && text.includes("See the evidence") && !text.includes("Retry loading this patient")), "The public Profiler must observe the genuine current Retry chart after the empty old refetch").toBe(true);
      expect(terminalConflict.noteDecryptAdmissions(terminalConflict.account.winning.blob), "Only current Retry decrypts the genuine winning note after the old empty refetch").toHaveLength(1);
      expect(terminalConflict.root().root.findAllByType("textarea").find(node => node.props.placeholder === "Editing note…")?.props.value).toBe("My preserved authenticated edit");
      terminalConflict.clean();
    } finally { await terminalConflict.retire(); }
  }
}, 60000);

it("refuses a hidden recording URL after Back retires a held native audio response", async () => {
  const chart = await openNativeChart({ holdAudio: true });
  try {
    await chart.evidence(); await chart.press("play recording"); await chart.audioArrives();
    await chart.press("Back to all patterns"); await chart.finishAudio();
    expect(chart.root().root.findAllByType("audio")).toHaveLength(0);
    expect([...chart.urls.values()].filter(record => record.digest === chart.account.audioDigest)).toHaveLength(0);
    expect(chart.text()).toContain("See the evidence");
    expect(chart.keyUnwrapResults.filter(key => key.some(byte => byte !== 0)), "Every actual unwrapped patient data-key buffer is zero after Back retires the completed native audio response").toHaveLength(0);
    expect(chart.audioCiphertextDecryptAdmissions, "Back must retire the exact authenticated native audio ciphertext before any AES-GCM decrypt is admitted").toHaveLength(0);
    chart.clean();
  } finally { await chart.retire(); }
  // A SAS response belongs to its caseload view. Keep the same live App
  // session while public navigation retires that view; only native HTTP waits.
  for (const editBeforeRetirement of [false, true]) {
    const sas = await openNativeChart({ retiredSasDigest: true });
    try {
      await sas.beginHeldSas();
      await sas.retireSasThroughPatterns(editBeforeRetirement);
      await sas.finishRetiredSas();
      expect(sas.retiredSasDigestAdmissions(), "a retired SAS context cannot admit a native fingerprint digest of the authenticated public wrap key").toEqual([]);
      expect(sas.text()).toContain("See the evidence");
      sas.clean();
    } finally { await sas.retire(); }
  }
  // Repeat the same live code/patient tuple after a genuine verified SAS.
  // Only the second real HTTP response waits; inspect its public Checking view.
  {
    const repeated = await openNativeChart({ repeatedSas: true });
    try {
      await repeated.beginRepeatedSas();
      expect(repeated.root().root.findAll(node => node.props["data-testid"] === "pairing-sas").map(node => node.children.join("")), "The first genuine native verification code is visible").toEqual(["123456"]);
      expect(repeated.firstRepeatedSasDigestAdmissions().map(row => ({ algorithm: row.algorithm, publicSpkiBase64: row.publicSpkiBase64 })), "The first current SAS admits the genuine native SHA-256 digest of this authenticated public SPKI").toEqual([{ algorithm: "SHA-256", publicSpkiBase64: repeated.account.publicKey }]);
      await repeated.beginSecondHeldSas();
      expect(repeated.button("Checking…").props.disabled, "The second same-tuple native request remains pending under its public Checking control").toBe(true);
      expect(repeated.root().root.findAll(node => node.props["data-testid"] === "pairing-sas"), "Starting another current SAS check hides the previous verification code while the real second response is pending").toHaveLength(0);
      await repeated.finishRepeatedSas();
      expect(repeated.root().root.findAll(node => node.props["data-testid"] === "pairing-sas").map(node => node.children.join("")), "The genuine second native response can publish its own verification code").toEqual(["123456"]);
      repeated.clean();
    } finally {
      // Own the pending original SAS while its current App/API owner is live,
      // including when the primary visibility assertion above failed.
      try { await repeated.finishPendingRepeatedSas(); }
      finally { await repeated.retire(); }
    }
  }
}, 60000);

it("keeps healthy native playback and explicit Stop available as a public control", async () => {
  const chart = await openNativeChart();
  try {
    await chart.evidence(); await chart.press("play recording"); await chart.audioVisible();
    const url = String(chart.root().root.findByType("audio").props.src);
    await chart.press("stop recording");
    expect(chart.root().root.findAllByType("audio")).toHaveLength(0);
    expect(chart.urls.get(url)?.active).toBe(false);
    expect(chart.text()).toContain("play recording");
    expect(chart.audioCiphertextDecryptAdmissions, "Healthy public playback admits the exact authenticated native audio ciphertext once").toHaveLength(1);
    expect(chart.keyUnwrapResults.length).toBeGreaterThan(0);
    expect(chart.keyUnwrapResults.filter(key => key.some(byte => byte !== 0))).toHaveLength(0);
    chart.clean();
  } finally { await chart.retire(); }
  // An authenticated patient row with an empty id is accepted by the current API parser.
  // Enter through App and public evidence/play controls; retain genuine native key-buffer identities.
  const missingId = await openNativeChart({ emptyPatientId: true });
  try {
    await missingId.evidence();
    const before = missingId.keyUnwrapResults.length;
    await missingId.press("play recording"); await missingId.finishKeyUnwraps();
    expect(missingId.root().root.findAllByType("audio")).toHaveLength(0);
    expect(missingId.keyUnwrapResults.slice(before).filter(key => key.some(byte => byte !== 0))).toHaveLength(0);
    missingId.clean();
  } finally { await missingId.retire(); }
  // The real HTTP parser accepts null backup_codes. A completed proof must
  // retire setup credentials even when that wire response cannot open codes.
  const mfa = await openNativeChart({ nullBackupCodesMfa: true });
  try {
    await mfa.input("Authenticator code", "123456"); await mfa.press("Enable two-factor authentication");
    await mfa.completed("native null backup-code response returned to setup", () => mfa.mfaEnableBodies.length === 1 && mfa.text().includes("Enable two-factor authentication"));
    expect(mfa.root().root.findAllByType("code").map(node => node.children.join("")), "native null backup-code response retires both public setup disclosures").toEqual(["", ""]);
    const factor = mfa.root().root.findAllByType("input").find(node => node.props.autoComplete === "one-time-code");
    if (!factor) throw new Error("SetupError: public mandatory enrollment input missing");
    expect(factor.props.value, "native null backup-code response clears the public authenticator field").toBe("");
    await mfa.input("Authenticator code", "123456"); await mfa.press("Enable two-factor authentication");
    await mfa.completed("second native proof request refused", () => mfa.mfaEnableBodies.length === 2 && mfa.text().includes("That authenticator code was not accepted"));
    expect(mfa.mfaEnableBodies[1], "second public proof request uses the retired blank enrollment verifier").toEqual({ verifier: "", code: "123456" });
    mfa.clean();
  } finally {
    try { await mfa.press("Cancel and sign out"); }
    finally { await mfa.retire(); }
  }
  // Retry is a public load action on this same mounted chart. Complete the
  // old authenticated native entry only while its selection is hidden, then
  // open a different pattern whose own native response remains held.
  {
    const retry = await openNativeChart({ retryEvidence: true });
    try {
      await retry.pressPatternEvidence("Earlier native pattern");
      await retry.retryEvidenceArrives("earlier");
      await retry.press("Retry loading this patient");
      await retry.completed("public replacement patterns and notes", () => retry.text().includes("Earlier native pattern") && retry.text().includes("Current native pattern") && retry.text().includes("Original authenticated note") && !retry.text().includes("Retry loading this patient"));
      await retry.finishRetiredRetryEvidence();
      expect(retry.text()).not.toContain("Authenticated audio evidence");
      await retry.pressPatternEvidence("Current native pattern");
      await retry.retryEvidenceArrives("current");
      expect(retry.text(), "A newly selected pattern cannot expose hidden plaintext completed before its held native evidence response").not.toContain("Authenticated audio evidence");
      expect(retry.text()).toContain("Decrypting the entries behind this pattern…");
      retry.clean();
    } finally { await retry.retire(); }
  }
  // Retire a real paginated note traversal through the current public Retry.
  // The old valid first page completes only after replacement notes publish.
  {
    const notes = await openNativeChart({ retiredNotesPagination: true });
    try {
      await notes.notesFirstPageArrives();
      await notes.press("Retry loading this patient");
      await notes.completed("current authenticated replacement notes", () => notes.text().includes("Original authenticated note") && notes.text().includes("See the evidence") && !notes.text().includes("Retry loading this patient"));
      await notes.finishHeldNotesFirstPage();
      expect(notes.retiredNoteDispatches(), "A retired note traversal must not send its continuation page after public Retry").toEqual([]);
      expect(notes.text()).toContain("Original authenticated note");
      notes.clean();
    } finally { await notes.retire(); }
  }
  // A real successful HTTP205 is malformed for this patient-list JSON
  // protocol. Preserve the exact native consumer error when its first public
  // rejection observer signs out through the current rendered control.
  {
    const empty = await openNativeChart({ native205Patients: true });
    try {
      await empty.beginNative205Patients();
      await empty.finishPendingNative205Patients();
      const result = empty.native205Errors();
      expect(result.exportedError, "A successful native null-body JSON rejection preserves its original SyntaxError identity across public Sign out").toBe(result.nativeError);
      expect(result.nativeError).toBeInstanceOf(SyntaxError);
      expect(result.signouts).toBe(1);
      expect(empty.text()).toContain("Sign in");
      empty.clean();
    } finally {
      try { await empty.finishPendingNative205Patients(); }
      finally { await empty.retire(); }
    }
  }
}, 60000);
