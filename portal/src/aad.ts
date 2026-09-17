/**
 * Canonical AAD construction — byte-identical to
 * backend/app/security/crypto.py's build_aad and mobile/src/crypto/aad.ts.
 *
 * The backend canonicalizes with Python json.dumps(..., ensure_ascii=True):
 * a compact JSON array in which every UTF-16 code unit >= 0x7F is escaped
 * as \uXXXX (astral characters therefore appear as surrogate-pair escapes).
 * Python's ensure_ascii range is "outside 0x20..0x7E", so DEL (0x7F) IS
 * escaped — JS JSON.stringify keeps such characters raw, hence this pass.
 * Control characters (\b \f \n \r \t) and quotes/backslash use identical
 * short escapes in both languages and need no handling here.
 *
 * shared/vectors.json pins this byte-for-byte with non-ASCII and astral
 * cases; if you change anything here, the vector tests fail loudly.
 */

function toEnsureAscii(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    out += code >= 0x7f ? "\\u" + code.toString(16).padStart(4, "0") : text[i]!;
  }
  return out;
}

export function buildAad(...parts: string[]): Uint8Array<ArrayBuffer> {
  const arrayJson = JSON.stringify(parts);
  // The JSON structure itself is pure ASCII after this pass; only string
  // contents could contain non-ASCII, and JSON.stringify escapes structural
  // characters itself — escaping the WHOLE serialization is safe.
  // (TextEncoder's result is always a fresh ArrayBuffer; the annotation
  // exists because the lib types it as ArrayBufferLike.)
  return new TextEncoder().encode(toEnsureAscii(arrayJson)) as Uint8Array<ArrayBuffer>;
}
