/**
 * Canonical AAD construction — pure, dependency-free, and byte-identical to
 * backend/app/security/crypto.py's build_aad.
 *
 * The backend canonicalizes with Python json.dumps(..., ensure_ascii=True):
 * a compact JSON array in which every UTF-16 code unit >= 0x7F is escaped
 * as \uXXXX (astral characters therefore appear as surrogate-pair escapes).
 * Python's ensure_ascii range is "outside 0x20..0x7E", so DEL (0x7F) IS
 * escaped on both platforms — verified against CPython and vectors.json.
 * JS JSON.stringify keeps such characters raw — so we post-process. Control
 * characters (\b \f \n \r \t) and the quotes/backslash use identical
 * short escapes in both languages and need no handling here.
 *
 * shared/vectors.json pins this byte-for-byte with non-ASCII and astral
 * cases; if you change anything in this file, regenerate vectors and run
 * `npm test` on BOTH platforms before shipping.
 */

function escapeAsciiChar(code: number): string {
  return "\\u" + code.toString(16).padStart(4, "0");
}

function toEnsureAscii(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    out += code >= 0x7f ? escapeAsciiChar(code) : text[i];
  }
  return out;
}

export function buildAad(...parts: string[]): Buffer {
  const arrayJson = JSON.stringify(parts);
  // The JSON structure itself is pure ASCII after this pass; only the
  // string contents could contain non-ASCII, and JSON.stringify escapes
  // structural characters itself, so escaping the WHOLE serialization is
  // safe: nothing outside string literals can be >= 0x7F.
  // Stryker disable StringLiteral
return Buffer.from(toEnsureAscii(arrayJson), "utf8");
  // Stryker restore StringLiteral
}
