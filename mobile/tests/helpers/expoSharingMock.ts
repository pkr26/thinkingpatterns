import { vi } from "vitest";
export const isAvailableAsync = vi.fn(async () => true);
export const shareAsync = vi.fn(async (_uri: string, _options?: object) => {});
