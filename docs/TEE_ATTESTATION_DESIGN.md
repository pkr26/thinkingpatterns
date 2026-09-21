# TEE attestation at the enclave seam — design note (Phase 3, 2026-09-21)

Status: DESIGN ONLY. This is the interim-server path's end-state answer
to "a compromised server can read content during processing windows"
(DPIA risk table). The on-device brain port (mobile/src/brain/PORT.md)
removes the window entirely; TEE attestation bounds the risk for the
transitional period when analysis still runs server-side.

## Threat model

Today the single-use processing session holds the data key in process
memory (≤5 min TTL, single-use, zeroized). A compromised HOST (kernel,
hypervisor, operator) can read that memory. TEE attestation narrows
this to: the key is readable only by code running inside a hardware
attested enclave, and the CLIENT verifies the attestation BEFORE
shipping the key.

## The seam (deliberately unchanged)

`app/security/enclave.py` is already an in-process SEAM — the API shape
(SecureProcessingContext, key lifetime, zeroization hooks) is what a
TEE-backed implementation must satisfy. The application layer does not
change; only the seam's backing does.

## Client-verified attestation flow (the design)

1. The client fetches the server's attestation: a hardware quote (SGX /
   TDX / SEV-SNP) over the enclave's measurement (MRENCLAVE-equivalent)
   AND a freshness proof (quote contains a client-supplied nonce —
   replayed quotes fail).
2. The client policy-pins the expected measurement: the FIRST time it
   sees a measurement it records it; a CHANGED measurement requires
   explicit user re-consent (same posture as TLS pinning + a warning).
3. Only after (1)+(2) pass does the client open the processing session
   — the existing `POST /processing/sessions` payload travels inside
   the attested channel (TLS to the host, then the enclave's sealed
   channel semantics per deployment target).
4. The quote's runtime properties assert: debug OFF, production keys.

## Operator contract

- Deployment: an enclave-capable node pool (the compose file gains a
  profile; non-TEE deployments keep today's behavior and the DPIA
  residual row stays).
- The measurement is derived from the release image digest — it inherits
  the existing digest-pinned release pipeline (release.yml) and ships in
  the release env asset next to the image reference.
- Attestation verification code lives CLIENT-SIDE (mobile), and its
  test vectors live in shared/ like every other cross-platform
  contract.

## Why this document exists before the code

The audit's Phase 3 listed TEE attestation as deployment work "for the
interim server path". The design above is the review artifact: it fixes
the client-verifiable guarantees and the operator contract BEFORE any
TEE SDK is chosen, so the eventual implementation is a substitution at
one seam rather than an architecture change.
