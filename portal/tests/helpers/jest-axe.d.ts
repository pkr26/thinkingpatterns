/** Type surface for jest-axe (the package ships no bundled declarations
 *  for vitest usage): axe() over a real DOM node. */
declare module "jest-axe" {
  import type { AxeResults } from "axe-core";
  export function axe(context: Element | string, options?: Record<string, unknown>): Promise<AxeResults>;
  export const toHaveNoViolations: Record<string, (this: unknown, ...args: unknown[]) => unknown>;
}
