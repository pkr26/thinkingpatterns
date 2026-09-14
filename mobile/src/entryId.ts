/**
 * Client entry id generation.
 *
 * The id is the dedupe key for the whole sync path: the server enforces
 * uniqueness per account (a re-upload 409s and is treated as success), so
 * an id COLLISION silently discards an entry. The old `e-<date>-<ms36>`
 * suffix (Date.now in base36) collided across two devices saving in the
 * same millisecond. The suffix is now 9 random bytes (72 bits) from the
 * crypto engine — quick-crypto on device, node:crypto in tests — so
 * cross-device collisions are a practical impossibility.
 *
 * The shape stays inside the contract band: client.deleteEntry validates
 * [A-Za-z0-9_-]{1,64} before any id reaches a URL path, and the backend
 * pins the same pattern (backend/app/schemas.py CLIENT_ID_PATTERN).
 * base64url output ([A-Za-z0-9_-], no padding) satisfies both.
 */
import { engine } from "./crypto/engine";

export function newClientEntryId(entryDate: string): string {
  const suffix = engine
    .randomBytes(9)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `e-${entryDate}-${suffix}`;
}
