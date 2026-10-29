import { bootstrapNotifications } from "./notification-bootstrap";

try {
  bootstrapNotifications("worker");
  // Run in this process so SIGTERM reaches the worker's bounded-attempt handler.
  await import("./notifications");
} catch {
  console.error(
    "Notification worker bootstrap failed; check protected deployment configuration.",
  );
  process.exitCode = 1;
}
