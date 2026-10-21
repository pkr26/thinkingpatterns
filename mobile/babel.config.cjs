/** Expo native transforms; CommonJS is required by this package's module type. */
const pkg = require("./package.json");

/** Replace value-position reads of __APP_VERSION__ with the manifest
 *  version literal. Property positions (object keys, non-computed member
 *  accesses) are skipped so the transform never rewrites unrelated code. */
function appVersionInline({ types }) {
  return {
    name: "mindpattern-app-version-inline",
    visitor: {
      Identifier(path) {
        if (!["__APP_VERSION__", "__API_ORIGIN__"].includes(path.node.name)) return;
        const parent = path.parent;
        if (types.isMemberExpression(parent) && parent.property === path.node && !parent.computed) return;
        if (types.isObjectProperty(parent) && parent.key === path.node) return;
        if (path.node.name === "__API_ORIGIN__") {
          const origin = process.env.MINDPATTERN_API_ORIGIN;
          if (origin) {
            const parsed = new URL(origin);
            if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || /\.(example|test|invalid)(?:\.|$)/.test(parsed.hostname)) throw new Error("MINDPATTERN_API_ORIGIN must be a real HTTPS origin without credentials or a path");
            path.replaceWith(types.stringLiteral(parsed.origin));
          } else path.replaceWith(types.nullLiteral());
        } else path.replaceWith(types.stringLiteral(pkg.version));
      },
    },
  };
}

module.exports = {
  presets: ["babel-preset-expo"],
  plugins: [appVersionInline],
};
