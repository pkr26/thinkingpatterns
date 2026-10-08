/** Keep test-only state controls pristine while production behavior stays mutated.
 * Calls are limited to exports verified to have no production consumers:
 * __...ForTests, setSecureStoreBackend, and resetAnalysisGenerationMirrors.
 * The control function and arguments are evaluated before this synchronous scope.
 */
export function runTestControl<Args extends unknown[], Result>(control: (...args: Args) => Result, ...args: Args): Result {
  const namespace = (globalThis as typeof globalThis & { __stryker__?: { activeMutant?: string } }).__stryker__;
  if (!namespace) return control(...args);
  const active = namespace.activeMutant;
  try {
    namespace.activeMutant = undefined;
    return control(...args);
  } finally {
    namespace.activeMutant = active;
  }
}
