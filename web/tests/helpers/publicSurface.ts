/** Compact public element output for readable presentation contracts.
 * React-generated field ids retain their association while being normalized;
 * callbacks are exercised by behavior tests rather than serialized here. */
export function publicSurface(tree: unknown): string {
  const ids = new Map<string, string>();
  const today = new Date().toISOString().slice(0, 10);
  const lines: string[] = [];
  const normalize = (value: unknown): unknown => {
    if (typeof value === "function" || value === undefined) return undefined;
    if (typeof value === "string" && /^(?:«r[^»]*»|_[rR]_[a-zA-Z0-9]+_)$/.test(value)) {
      if (!ids.has(value)) ids.set(value, `field-association-${ids.size + 1}`);
      return ids.get(value);
    }
    if (value === today) return "CURRENT_DATE";
    return value;
  };
  const visit = (node: unknown, depth: number): void => {
    if (Array.isArray(node)) { node.forEach(child => visit(child, depth)); return; }
    if (node === null) return;
    if (typeof node === "string" || typeof node === "number") {
      lines.push(`${"  ".repeat(depth)}${JSON.stringify(normalize(node))}`);
      return;
    }
    const element = node as { type: string; props: Record<string, unknown>; children: unknown[] | null };
    const attributes = Object.entries(element.props).sort(([a], [b]) => a.localeCompare(b)).flatMap(([key, value]) => {
      const normalized = normalize(value);
      return normalized === undefined ? [] : [`${key}=${JSON.stringify(normalized)}`];
    });
    lines.push(`${"  ".repeat(depth)}<${element.type}${attributes.length ? " " + attributes.join(" ") : ""}>`);
    element.children?.forEach(child => visit(child, depth + 1));
  };
  visit(tree, 0);
  return lines.join("\n");
}
