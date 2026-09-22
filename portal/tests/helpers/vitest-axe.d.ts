/** Register jest-axe's matcher on vitest's Assertion (module augmentation —
 *  must be a module file to merge with, not replace, vitest's types). */
import "vitest";

declare module "vitest" {
  interface Assertion<T = any> {
    toHaveNoViolations(): T;
  }
}

export {};
