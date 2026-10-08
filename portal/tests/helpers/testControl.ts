import { drainPortalDraftWritesForTests as drainDraftWrites } from "../../src/noteDrafts";

/** Fixture controls have no application consumers. Keep their setup pristine
 * while the public operation under test retains its active mutation. */
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

/** Only a campaign restricted to test-control operators may suspend activation
 * across this async fixture drain. Ordinary production campaigns keep queued
 * encrypted writes mutated while the fixture waits for them to finish. */
export async function drainPortalDraftWritesForTests(): Promise<void> {
  const namespace = (globalThis as typeof globalThis & { __stryker__?: { activeMutant?: string } }).__stryker__;
  if (process.env.PORTAL_MUTATION_TEST_CONTROLS_ONLY !== "1" || !namespace) return drainDraftWrites();
  const active = namespace.activeMutant;
  try {
    namespace.activeMutant = undefined;
    await drainDraftWrites();
  } finally {
    namespace.activeMutant = active;
  }
}
