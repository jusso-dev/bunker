// TypeScript 7.0 removed the legacy JS compiler API required by typescript-eslint
// and openapi-typescript until TypeScript 7.1 ships the new API. Provide TS 6.0
// directly to those tools so the workspace itself can run native TypeScript 7.0.
const TS6_CONSUMERS = new Set([
  "openapi-typescript",
  "typescript-eslint",
  "ts-api-utils",
]);

function readPackage(pkg) {
  if (
    TS6_CONSUMERS.has(pkg.name) ||
    (typeof pkg.name === "string" && pkg.name.startsWith("@typescript-eslint/"))
  ) {
    if (pkg.peerDependencies && pkg.peerDependencies.typescript) {
      delete pkg.peerDependencies.typescript;
      pkg.dependencies = {
        ...pkg.dependencies,
        typescript: "^6.0.3",
      };
    }
  }
  return pkg;
}

module.exports = {
  hooks: {
    readPackage,
  },
};
