// Deployment boundary only. Application protectedFile validators remain unchanged.
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { destinations, signingSecret } from "../src/notifications/config";

const runtime = "/run/bunker/notifications";
const filename = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;

// Only this explicitly trusted, read-only deployment mount may contain symlinks.
// Resolve Kubernetes ..data projections, but reject escapes and non-regular files.
function materialize(source: string, name: string, output: string) {
  const root = realpathSync(source);
  const input = realpathSync(join(root, name));
  const rel = relative(root, input);
  if (!rel || rel === ".." || rel.startsWith(".." + sep) || isAbsolute(rel))
    throw new Error("Notification projection escapes its mount");
  const fd = openSync(
    input,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 65536)
      throw new Error("Invalid notification projection");
    const bytes = readFileSync(fd);
    if (bytes.length > 65536)
      throw new Error("Notification projection too large");
    writeFileSync(output, bytes, { flag: "wx", mode: 0o600 });
    chmodSync(output, 0o600);
  } finally {
    closeSync(fd);
  }
}

export function bootstrapNotifications(
  role: "api" | "worker",
  paths = {
    runtime,
    configSource: "/run/secrets/notification-config",
    signingSource: "/run/secrets/notification-signing",
  },
) {
  const enabled = process.env.BUNKER_NOTIFICATIONS_ENABLED ?? "false";
  delete process.env.BUNKER_WEBHOOK_CONFIG_FILE;
  if (!["true", "false"].includes(enabled))
    throw new Error("BUNKER_NOTIFICATIONS_ENABLED must be true or false");
  if (enabled === "false") {
    if (role === "worker") throw new Error("Notification worker is disabled");
    return;
  }
  if (process.env.BUNKER_WEBHOOK_TEST_TRANSPORT_FILE)
    throw new Error("Test transport forbidden in deployed notifications");
  // The parent is a private UID-owned tmpfs. Never follow a stale runtime symlink.
  try {
    const stat = lstatSync(paths.runtime);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      throw new Error("Unsafe notification runtime directory");
    rmSync(paths.runtime, { recursive: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  mkdirSync(paths.runtime, { mode: 0o700 });
  chmodSync(paths.runtime, 0o700);
  const config = join(paths.runtime, "config.json");
  materialize(paths.configSource, "config.json", config);
  process.env.BUNKER_WEBHOOK_CONFIG_FILE = config;
  try {
    const configured = destinations();
    const signing = join(paths.runtime, "signing");
    // Deployment uses file references only, confined to the worker's private mount.
    // The API validates references without opening or mounting signing material.
    for (const d of configured) {
      if (
        !d.secretFile ||
        dirname(d.secretFile) !== signing ||
        !filename.test(basename(d.secretFile))
      )
        throw new Error(
          "Deployed notification secrets must reference private signing files",
        );
    }
    if (role === "worker") {
      mkdirSync(signing, { mode: 0o700 });
      for (const name of new Set(
        configured.map((d) => basename(d.secretFile!)),
      ))
        materialize(paths.signingSource, name, join(signing, name));
      for (const d of configured) signingSecret(d);
    }
  } catch {
    delete process.env.BUNKER_WEBHOOK_CONFIG_FILE;
    rmSync(paths.runtime, { recursive: true });
    throw new Error("Invalid protected notification deployment configuration");
  }
}
