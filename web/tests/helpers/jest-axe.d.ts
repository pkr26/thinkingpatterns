/** jest-axe 11 ships no type declarations; this local module shape covers
 *  the two exports the a11y suite uses. (The portal's older install
 *  resolved types transitively; declaring them locally is honest either
 *  way.) */
declare module "jest-axe" {
  export function axe(
    container: HTMLElement | string | Node,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  export const toHaveNoViolations: Record<string, unknown>;
}
