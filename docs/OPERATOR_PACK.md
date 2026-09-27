# Operator & compliance pack — MindPattern

Everything an operator needs to review, complete, and sign before
serving this product to the public. Each document states what the
PRODUCT already does (verified against the tree, 2026-09-26) and what
the OPERATOR must decide, fill, or sign. Items marked `OPERATOR-FILL`
or `LEGAL-REVIEW` are deliberately incomplete: inventing a controller
identity or a legal determination in source control would be worse
than leaving the blank.

| Document | What it is | Operator action |
|---|---|---|
| `PRIVACY_POLICY_TEMPLATE.md` | Plain-language privacy policy mapped to the actual data flows (journal ciphertext, metadata, audit log, therapist linkage, LLM egress, export/delete) | Complete `LEGAL-REVIEW`/`OPERATOR-FILL` blanks, legal review, publish; mirror the in-app copy |
| `DATA_RETENTION_SCHEDULE.md` | Every retention number found in code/config in one table: what, where, how long, deletion path | Verify against your deployment's actual env values; attach to the RoPA |
| `SUBPROCESSOR_BAA_REGISTER.md` | Subprocessor register template (LLM provider, hosting, backup target) with BAA-required flags | Fill per deployment; execute DPAs/BAAs before enabling each processor |
| `SECURITY_POLICY.md` | The operator-side security policy: what this repo enforces in code vs. what the operating organization must own (secrets custody, patching, branch protection, monitoring, incident clocks) | Adopt, adapt to your organization, sign |
| `security.txt.example` | RFC 9116 disclosure-contact template (PGP note included) | Copy to the served origin's `/.well-known/security.txt`, fill contact + expiry |
| `DPIA_SKELETON.md` | Signable DPIA template (Art. 35(7) elements from code reality, age-gate control, Art. 36 trigger, signature blocks) | Fill §0 and the risk-table residuals; sign §6 |
| `INCIDENT_RUNBOOK.md` | Severity ladder, first-five-minutes, breach clocks (GDPR 72h + FTC HBNR 60-day), contact-role table | Fill every `OPERATOR-FILL` contact at deploy time; rehearse |
| `../deploy/README.md` | Digest-pinned deployment contract, secrets files, branch-protection setup, rollback | Follow; keep digests re-pinned deliberately |

Reading order for a first deployment: SECURITY_POLICY (can we operate
this safely?) → DATA_RETENTION_SCHEDULE + SUBPROCESSOR_BAA_REGISTER
(what do we retain and who processes it?) → PRIVACY_POLICY_TEMPLATE
(what do we tell users?) → DPIA_SKELETON (sign it) → INCIDENT_RUNBOOK
(fill the contacts, rehearse the restore).

Product-side facts these documents rely on (all code-verified
2026-09-26): client-side AES-256-GCM everywhere, random data-key
envelope v2 (v1 legacy supported), server-side scrypt N=2¹⁷ verifiers,
purpose-split server secrets, exact sliding-window rate limits, forward
hash-chained access audit log, hard cascade account deletion with a
surviving 730-day audit trail, consent-gated and off-by-default LLM
egress, offline crisis resources in every client. The honest residual
set lives in `SECURITY_RESIDUALS.md` — read it alongside this pack; a
compliance story that hides the residuals is not this product's story.
