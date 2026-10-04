/** Type declarations for tools/securityTxt.mjs (the build gate the unit
 *  test imports — the file itself stays plain node ESM for add-sri.mjs). */
export declare const SECURITY_TXT_PLACEHOLDERS: string[];
export declare function securityTxtPlaceholderFindings(text: string): string[];
export declare function assertNoSecurityTxtPlaceholders(text: string): void;
export declare function renderSecurityTxt(
  values: { contact: string; canonical: string; expires: string },
  now?: Date,
): string;
