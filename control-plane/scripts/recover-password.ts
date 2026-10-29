// Explicit instance-operator access, like link-identity. No email or provider reset.
import { open, lstat, realpath } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { z } from "zod";
import { database, transaction } from "../src/lib/db";
import { issueRecovery } from "../src/lib/human-lifecycle";

const [confirmation, user, output, ...extra] = process.argv.slice(2);
if (
  confirmation !== "--confirm-local-recovery" ||
  !z.uuid().safeParse(user).success ||
  !output ||
  !isAbsolute(output) ||
  extra.length
)
  throw new Error(
    "Usage: recover-password --confirm-local-recovery USER_UUID /private/directory/new-token-file",
  );
const parent = dirname(output);
const directory = await lstat(parent);
if (
  !directory.isDirectory() ||
  directory.uid !== process.getuid?.() ||
  (directory.mode & 0o077) !== 0 ||
  (await realpath(parent)) !== parent
)
  throw new Error(
    "Output directory must be owned by this operator, mode 0700, and contain no symlinks",
  );
// Exclusive creation prevents replacement or following an existing file/link.
const file = await open(
  output,
  constants.O_WRONLY |
    constants.O_CREAT |
    constants.O_EXCL |
    constants.O_NOFOLLOW,
  0o600,
);
try {
  await transaction(async (db) => {
    const secret = await issueRecovery(db, user);
    await file.writeFile(secret + "\n");
    await file.sync();
  });
  console.log(
    "One-use local recovery written to the protected file; expires in 15 minutes. No message was sent.",
  );
} catch {
  // Do not log database errors or the token. A failed transaction leaves no valid token.
  await file.truncate(0);
  process.exitCode = 1;
  console.error("Recovery issuance failed; no recovery was committed.");
} finally {
  await file.close();
  await database().end();
}
