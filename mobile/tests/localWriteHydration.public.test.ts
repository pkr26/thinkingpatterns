import { expect, it, vi } from "vitest";
import { hydrateLocalSessionOwner, subscribeLocalWriteScope } from "../src/localWriteGuard";

it("notifies a subscriber when hydration changes owner, but not when it repeats the same owner", async () => {
  await Promise.resolve();
  const observed = vi.fn();
  const unsubscribe = subscribeLocalWriteScope(observed);
  try {
    hydrateLocalSessionOwner("hydration-notification-owner");
    expect(observed).not.toHaveBeenCalled();
    await Promise.resolve();
    expect(observed).toHaveBeenCalledTimes(1);
    hydrateLocalSessionOwner("hydration-notification-owner");
    await Promise.resolve();
    expect(observed).toHaveBeenCalledTimes(1);
  } finally { unsubscribe(); }
});
