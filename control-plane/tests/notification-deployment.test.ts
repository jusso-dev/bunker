import { test } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes, randomUUID } from "node:crypto";
import { bootstrapNotifications } from "../scripts/notification-bootstrap";
import { protectedFile } from "../src/identity/files";

// No operator configuration, database, network or real secrets.
test("notification deployment materializes projections and separates API/worker secrets", async (t) => {
  const original = { ...process.env };
  const dir = mkdtempSync(join(tmpdir(), "bunker-notification-bootstrap-"));
  const paths = {
    runtime: join(dir, "runtime"),
    configSource: join(dir, "config"),
    signingSource: join(dir, "signing"),
  };
  const secret = randomBytes(32);
  const key = join(paths.runtime, "signing", "receiver.key");
  const destination = {
    tenantId: randomUUID(),
    id: "primary-v1",
    url: "https://receiver.example.test/bunker-events",
    secretFile: key,
  };
  const writeConfig = (entries: unknown[] = [destination]) =>
    writeFileSync(
      join(paths.configSource, "..data", "config.json"),
      JSON.stringify({ destinations: entries }),
      { mode: 0o640 },
    );
  try {
    delete process.env.BUNKER_NOTIFICATIONS_ENABLED;
    delete process.env.BUNKER_WEBHOOK_TEST_TRANSPORT_FILE;
    process.env.BUNKER_WEBHOOK_CONFIG_FILE = "/unexpected/config";
    await t.test(
      "disabled default does not read mounts or preserve injected config",
      () => {
        bootstrapNotifications("api", paths);
        assert.equal(process.env.BUNKER_WEBHOOK_CONFIG_FILE, undefined);
        assert.equal(existsSync(paths.runtime), false);
        assert.throws(
          () => bootstrapNotifications("worker", paths),
          /disabled/,
        );
        process.env.BUNKER_NOTIFICATIONS_ENABLED = "yes";
        assert.throws(
          () => bootstrapNotifications("api", paths),
          /true or false/,
        );
      },
    );
    process.env.BUNKER_NOTIFICATIONS_ENABLED = "true";
    mkdirSync(join(paths.configSource, "..data"), { recursive: true });
    symlinkSync("..data/config.json", join(paths.configSource, "config.json"));
    writeConfig();
    await t.test("API validates projected config with no signing mount", () => {
      assert.throws(() =>
        protectedFile(join(paths.configSource, "config.json")),
      );
      bootstrapNotifications("api", paths);
      const config = join(paths.runtime, "config.json");
      assert.equal(lstatSync(config).isSymbolicLink(), false);
      assert.equal(lstatSync(config).mode & 0o777, 0o600);
      assert.equal(lstatSync(paths.runtime).mode & 0o777, 0o700);
      if (process.getuid) assert.equal(lstatSync(config).uid, process.getuid());
      assert.equal(
        JSON.parse(protectedFile(config).toString()).destinations[0].secretFile,
        key,
      );
      assert.equal(existsSync(key), false);
    });
    mkdirSync(join(paths.signingSource, "..data"), { recursive: true });
    writeFileSync(join(paths.signingSource, "..data", "receiver.key"), secret, {
      mode: 0o640,
    });
    symlinkSync(
      "..data/receiver.key",
      join(paths.signingSource, "receiver.key"),
    );
    await t.test(
      "worker copies signing bytes exactly, then validators accept regular 0600 files",
      () => {
        bootstrapNotifications("worker", paths);
        assert.deepEqual(protectedFile(key), secret);
        assert.equal(lstatSync(key).isSymbolicLink(), false);
        assert.equal(lstatSync(key).mode & 0o777, 0o600);
        assert.equal(
          lstatSync(join(paths.runtime, "signing")).mode & 0o777,
          0o700,
        );
        if (process.getuid) assert.equal(lstatSync(key).uid, process.getuid());
        chmodSync(key, 0o640);
        assert.throws(() => protectedFile(key));
        bootstrapNotifications("worker", paths); // restart rematerializes; no stale files
        assert.deepEqual(protectedFile(key), secret);
        bootstrapNotifications("api", paths);
        assert.equal(existsSync(key), false);
      },
    );
    await t.test(
      "rejects signing env, escaping paths, absent keys and short secrets",
      () => {
        for (const secretFile of [
          "/run/bunker/secrets/ca.key",
          join(paths.runtime, "other.key"),
          key + "/../other.key",
        ]) {
          writeConfig([{ ...destination, secretFile }]);
          assert.throws(() => bootstrapNotifications("api", paths));
        }
        writeConfig([
          { ...destination, secretFile: undefined, secretEnv: "RECEIVER_KEY" },
        ]);
        assert.throws(() => bootstrapNotifications("api", paths));
        writeConfig([
          {
            ...destination,
            secretFile: join(paths.runtime, "signing", "missing.key"),
          },
        ]);
        assert.throws(() => bootstrapNotifications("worker", paths));
        writeConfig();
        writeFileSync(
          join(paths.signingSource, "..data", "receiver.key"),
          "too-short",
        );
        assert.throws(() => bootstrapNotifications("worker", paths));
        assert.equal(process.env.BUNKER_WEBHOOK_CONFIG_FILE, undefined);
        assert.equal(existsSync(paths.runtime), false);
        writeFileSync(
          join(paths.signingSource, "..data", "receiver.key"),
          secret,
        );
      },
    );
    await t.test(
      "rejects escaped projections, oversized files, directories and runtime symlinks",
      () => {
        const projected = join(paths.configSource, "config.json");
        rmSync(projected);
        writeFileSync(
          join(dir, "outside.json"),
          readFileSync(join(paths.configSource, "..data", "config.json")),
        );
        symlinkSync(join(dir, "outside.json"), projected);
        assert.throws(() => bootstrapNotifications("api", paths), /escapes/);
        rmSync(projected);
        mkdirSync(projected);
        assert.throws(() => bootstrapNotifications("api", paths));
        rmSync(projected, { recursive: true });
        writeFileSync(projected, Buffer.alloc(65537));
        assert.throws(() => bootstrapNotifications("api", paths));
        rmSync(paths.runtime, { recursive: true });
        symlinkSync(paths.configSource, paths.runtime);
        assert.throws(() => bootstrapNotifications("api", paths), /Unsafe/);
        assert.ok(
          existsSync(join(paths.configSource, "..data", "config.json")),
        );
        rmSync(paths.runtime);
      },
    );
    await t.test(
      "deployment forbids test transport even when NODE_ENV=test",
      () => {
        process.env.BUNKER_WEBHOOK_TEST_TRANSPORT_FILE = join(dir, "test.json");
        assert.throws(
          () => bootstrapNotifications("worker", paths),
          /Test transport forbidden/,
        );
      },
    );
  } finally {
    for (const name of [
      "BUNKER_NOTIFICATIONS_ENABLED",
      "BUNKER_WEBHOOK_CONFIG_FILE",
      "BUNKER_WEBHOOK_TEST_TRANSPORT_FILE",
    ]) {
      if (original[name] === undefined) delete process.env[name];
      else process.env[name] = original[name];
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
