/* Pre-paint theme resolution (dark-FOUC fix, hardening 2026-09-26 ii).
 *
 * This file is loaded SYNCHRONOUSLY in <head>, BEFORE the /app.css link,
 * so the token blocks resolve against the right data-theme on the very
 * first paint — a saved-dark or dark-OS user never sees a cream flash.
 * It must stay tiny, dependency-free, and side-effect-free beyond the
 * one attribute. src/theme.ts owns the same key (THEME_STORAGE_KEY) and
 * re-applies reactively; tests/theme.test.ts pins the two in sync.
 *
 * Plain JS on purpose: it runs before any bundle, and hashing an inline
 * copy into the CSP would add build plumbing for zero gain over this
 * same-origin, SRI-stamped file.
 */
(function () {
  "use strict";
  try {
    var pref = localStorage.getItem("mindpattern.theme.pref");
    var dark =
      pref === "dark" ||
      ((pref === "auto" || pref === null) &&
        typeof window.matchMedia === "function" &&
        window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
  } catch (e) {
    /* No localStorage/matchMedia (or no document): the :root light theme
       is the default — never block boot on a cosmetic preference. */
  }
})();
