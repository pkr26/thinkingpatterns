/**
 * Client entry id generation (ported from mobile's entryId.ts onto the
 * platform seam). The id is the dedupe key for the whole sync path: the
 * server enforces uniqueness per account (a re-upload 409s and is treated
 * as success), so an id COLLISION silently discards an entry — the suffix
 * is 9 random bytes (72 bits), so cross-device collisions are a practical
 * impossibility. base64url output satisfies the client+backend
 * [A-Za-z0-9_-]{1,64} contract band.
 */
import { randomBytes } from "./platform";

export function newClientEntryId(entryDate: string): string {
  const bytes = randomBytes(9);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const suffix = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `e-${entryDate}-${suffix}`;
}
