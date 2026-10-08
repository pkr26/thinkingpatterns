import "./browserSetup";
await import("../../src/strings").then(module => Promise.all([
  module.loadFullCatalogs("en"),
  module.loadFullCatalogs("es"),
]));
