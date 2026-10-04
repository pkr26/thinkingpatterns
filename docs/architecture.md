# Architecture and security model

Fathom consists of a FastAPI service, patient web and mobile clients, and a
therapist portal. Clients encrypt content before storage or sync. The backend
stores encrypted journal entries, insights, questions, wellbeing measures,
audio attachments, and clinician notes, together with the metadata needed to
route, authorize, paginate, and retain them.

## Encryption and analysis

The shipped clients derive a master key with PBKDF2-HMAC-SHA256 at 600,000
iterations. HKDF separates authentication and encryption purposes. The server
receives an authentication verifier and stores a scrypt-derived value; it never
needs the user's password. The default scrypt work factor is 131,072.

Content uses AES-256-GCM. Additional authenticated data binds ciphertext to its
account, object, and purpose so it cannot be moved between those contexts.
Shared cryptographic vectors under `shared/` verify the same constructions
across Python, React Native, and both browser clients.

Legacy v1 accounts derive the data key from the password-based master key.
V2 accounts hold a random data key inside a client-encrypted key envelope.
The declared `kdf_params` describe the client key schedule; Argon2id is accepted
in the metadata schema but is not implemented by the shipped clients.

Server analysis is an explicit exception to content confidentiality. A requested
recompute sends the data key into a short-lived, single-use processing session.
The service decrypts entries, runs deterministic analysis, encrypts the results,
and scrubs owned key/plaintext byte buffers. Python and JavaScript string copies
are reclaimed by their runtimes and cannot be reliably zeroized. This is an
in-process boundary, not a hardware enclave or TEE attestation guarantee.

The server enforces 30 distinct active days before analysis. Entry dates are
validated against account creation and the permitted timezone grace. See the
[analysis guide](analysis.md) for evidence thresholds and the on-device port.
Production recompute does not dispatch journal text to a narration-only LLM.
Separately consented transcription and translation remain distinct provider paths.

## Session custody and synchronization

The browser clients keep session tokens and unlocked keys in memory. Refreshing
or opening a new tab requires authentication. Idle locking and page lifecycle
handling close the unlocked session. Persisted queues and drafts contain
ciphertext scoped to the API origin and account.

Mobile persists its session token encrypted under a per-install key held by
Keychain or Keystore. There is no insecure-storage fallback. Derived content
keys remain memory-only; restarting the app returns to a locked state.
Optional biometric unlock wraps the data key with the current biometric set,
while password unlock remains available. Typed drafts are encrypted on disk;
a scoped RAM fallback can retain an unsaved draft across locking and is cleared
on sign-out. See [mobile session behavior](../mobile/README.md).

Sync is push-only; history reads retrieve account entries independently.
Creation is idempotent by client object ID. Updates use version comparison,
returning `version_conflict` when another writer won. Collection reads use
revision snapshots and restart on `collection_changed`. Clients surface
conflicts rather than silently replacing a newer version.

Logout revokes the presented token. Credential changes, key rotation, and
account deletion advance account-wide session state. Other devices observe
revocation on their next authenticated request.

## Password changes and recovery

A v2 envelope permits a credential/envelope change without re-encrypting the
corpus when the data key stays unchanged. A full patient data-key rotation uses
a persisted operation ID and staged ciphertext. The resumable rekey finalization
commits supported server ciphertext, credentials, the optional envelope,
sharing wraps, and session epoch together. Retrying a lost response must use
the same operation and body. A different generation fails closed.

Verified local replacements resume after fresh login. A superseded recovery kit
must be replaced. Recovery metadata and ciphertext formats are compatibility
contracts; changes require explicit migration and cross-client verification.

Clinician notes have separate key custody. Password changes atomically commit
the credential, rewrapped sharing key, and encrypted notes keyring under custody
version comparison. Historical note and revision keys remain in that keyring.
Sharing-identity replacement retains note custody and revokes grants addressed
to the retired key. Second-factor recovery codes do not recover forgotten
passwords or encryption keys.

## Therapist sharing

Therapist accounts register a P-256 sharing keypair. The server stores the public
key and an encrypted private-key blob. Account roles are enforced on the API;
therapists have no write endpoint for patient journal content.

A patient redeems a short-lived, single-use pairing code, checks the therapist's
identity and displayed key comparison values out of band, accepts the disclosure,
and re-authenticates. The client wraps its data key to the therapist's public
key using ECDH, HKDF, and AES-GCM. Pairing codes are stored as HMACs and consumed
atomically. Without the human comparison, identity discovery still trusts the
server relaying the key.

The portal unwraps the patient key locally and decrypts consented entries,
insights, wellbeing measures, and optionally retained audio. Caseload summaries
are encrypted to the therapist. Measures are displayed for clinician
interpretation; the application does not provide a diagnosis or severity verdict.

Therapist notes are independent encrypted records, accessible only to the
therapist. Edits require the base version and retain immutable revisions.
Patient or therapist account deletion removes the associated live records.

Therapists must enroll TOTP before accessing patient data. Enrollment and
sensitive factor changes require fresh authentication. Accepted codes are
single-use; saved recovery codes recover only the second factor.

Revocation immediately ends future API access and clears the grant's wrapped
key. It cannot retract content already decrypted by a recipient. Granting,
revoking, and accessing patient data produce access-audit records. Each chain
uses linked hashes and versioned HMAC seals; production also persists journal
heads outside the database to detect deleted tails. Audit metadata outlives
account deletion according to the configured retention policy.

## Safety and disclosure

Offline crisis resources are reachable from the clients without relying on the
API. The shared crisis-language catalog separates client dialog triggers from
broader suppression rules. Sensitive patterns render without quoting the
underlying phrase and are excluded from reflective question generation.

Observations carry supporting evidence. Repeated qualification over overlapping
windows is not independent statistical replication or clinical validation.
The [research guide](research.md) and [validation plan](VALIDATION_TO_90.md)
describe the evidence and its limits.

The server retains metadata including account names, dates, ciphertext sizes,
sharing relationships, and access-audit events. Salt lookup uses deterministic
decoys, but registration availability and longitudinal membership transitions
remain documented enumeration limits. See [security residuals](SECURITY_RESIDUALS.md).

## Deployment boundary

One active API process per database is supported. File and PostgreSQL advisory
locks reject additional owners; losing ownership fails readiness and protected
admission. In-memory key/session custody and counters are not distributed.

`users.is_active` is an operator-controlled incident-response lever checked by
authentication paths; no self-service API deactivates accounts with that flag.
See the [incident runbook](INCIDENT_RUNBOOK.md) before changing it.

Production startup rejects development secrets and SQLite. Requests have body,
time, rate, and storage limits. Proxy identity is trusted only from configured
direct peers; Uvicorn proxy-header rewriting remains disabled. The deployment
image disables request access logs and applies security response headers.

Mobile does not implement static TLS certificate pinning for self-hosted
endpoints. Android uses system trust; the iOS user-installed-CA limitation is
recorded in the residual-risk register. Deployment must provide TLS and protect
its reverse-proxy configuration.

Use the [deployment guide](../deploy/README.md),
[configuration and retention reference](configuration.md), and
[operator pack](OPERATOR_PACK.md) for production procedures and obligations.
