import { setTimeout } from "node:timers/promises";
import { database } from "../src/lib/db";
import { destinations, testTransport } from "../src/notifications/config";
import { runOnce } from "../src/notifications/worker";
let stopping = false;
let shutdownDeadline: NodeJS.Timeout | undefined;
function stop() {
  if (stopping) return;
  stopping = true;
  // Leave time before the deployment's 60-second grace. A wedged DB/socket must
  // not hold shutdown forever; outstanding jobs recover through fenced leases.
  shutdownDeadline = globalThis.setTimeout(() => {
    console.error("Notification worker shutdown deadline exceeded.");
    process.exit(1);
  }, 45000);
  shutdownDeadline.unref();
}
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
try {
  // Reject malformed operator config before starting. No network calls during validation.
  destinations();
  testTransport();
  do {
    const worked = await runOnce();
    if (process.argv.includes("--once")) break;
    if (!worked && !stopping) await setTimeout(1000);
  } while (!stopping);
} catch {
  // Do not log arbitrary database/transport errors: these can contain customer data or credentials.
  console.error(
    "Notification worker stopped; check database availability and protected configuration.",
  );
  process.exitCode = 1;
} finally {
  await database().end();
  if (shutdownDeadline) clearTimeout(shutdownDeadline);
}
