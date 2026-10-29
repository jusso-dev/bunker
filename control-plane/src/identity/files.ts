import {
  constants,
  openSync,
  fstatSync,
  readFileSync,
  closeSync,
} from "node:fs";
import { isAbsolute } from "node:path";
import { ApiError } from "../lib/security";

// Reject symlinks, non-regular files, oversized files, and group/world-readable secrets.
export function protectedFile(path: string | undefined): Buffer {
  if (!path || !isAbsolute(path))
    throw new ApiError(503, "Identity file reference must be absolute");
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (
      !stat.isFile() ||
      stat.size > 65536 ||
      (stat.mode & 0o077) !== 0 ||
      (process.getuid && ![0, process.getuid()].includes(stat.uid))
    )
      throw new Error();
    return readFileSync(fd);
  } catch {
    throw new ApiError(
      503,
      "Identity file is unavailable or insufficiently protected",
    );
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
export function gatewayKey() {
  const key = protectedFile(process.env.BUNKER_GATEWAY_SECRET_FILE);
  if (key.length !== 32)
    throw new ApiError(
      503,
      "Gateway secret must contain exactly 32 random bytes",
    );
  return key;
}
