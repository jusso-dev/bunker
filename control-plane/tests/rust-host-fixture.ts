import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fixtures, tlsCall } from "./identity-fixtures";

export async function exerciseRustHost(
  binary: string,
  f: ReturnType<typeof fixtures>,
  origin: string,
  hostOrigin: string,
  tenant: string,
  headers: Record<string, string>,
) {
  const root = realpathSync(f.dir);
  const repository = join(root, "rust-repository");
  const workspace = join(root, "rust-workspace");
  const config = join(root, "rust-host.toml");
  mkdirSync(workspace, { mode: 0o700 });
  const file = join(workspace, "fixture.txt");
  writeFileSync(file, "4821");
  const env = {
    ...process.env,
    BUNKER_PASSPHRASE: randomBytes(32).toString("hex"),
  };
  const invoke = async (args: string[], input = "", succeeds = true) => {
    const result = await new Promise<{
      code: number | null;
      stdout: string;
      stderr: string;
    }>((resolve, reject) => {
      const child = spawn(binary, ["--repo", repository, ...args], {
        env,
        stdio: ["pipe", "pipe", "pipe"],
        timeout: 30000,
      });
      let stdout = "",
        stderr = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.once("error", reject);
      child.once("close", (code) => resolve({ code, stdout, stderr }));
      child.stdin.end(input);
    });
    if (succeeds) assert.equal(result.code, 0, result.stderr);
    else assert.notEqual(result.code, 0);
    return result.stdout;
  };
  const human = async (path: string, body: unknown) =>
    tlsCall(`${origin}/api/tenants/${tenant}/${path}`, f.read("ca.pem"), {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
  const enrollment = await human("enrollments", {
    name: "Rust interoperability fixture",
  });
  assert.equal(enrollment.status, 201);
  f.write("rust-enrollment-token", JSON.parse(enrollment.body).token);
  writeFileSync(
    config,
    [
      `public_origin = ${JSON.stringify(origin)}`,
      `host_origin = ${JSON.stringify(hostOrigin)}`,
      `tenant = ${JSON.stringify(tenant)}`,
      `credential_directory = ${JSON.stringify(join(root, "rust-identity"))}`,
      `consumed_directory = ${JSON.stringify(join(root, "rust-consumed"))}`,
      `server_ca_file = ${JSON.stringify(join(root, "ca.pem"))}`,
      'storage_ref = "fixture-local"',
      'key_ref = "fixture-key"',
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  await invoke(["init"]);
  const identity = JSON.parse(
    await invoke([
      "host",
      "--config",
      config,
      "enroll",
      "--token-file",
      join(root, "rust-enrollment-token"),
    ]),
  );
  assert.equal(identity.tenant, tenant);
  const policy = await human("policies", {
    name: "Rust fixture policy",
    hostId: identity.host,
    intervalMinutes: 60,
    endOfSession: false,
    retentionDays: 30,
    exclusions: [],
    sizeCapBytes: 1048576,
    immutable: false,
    drCopy: false,
    residency: "unrestricted",
    storage: "local",
    storageRef: "fixture-local",
    keyRef: "fixture-key",
    massDeleteThreshold: 20,
    missedBackupMinutes: 120,
    restoreTestIntervalHours: 24,
    channels: ["ui"],
  });
  assert.equal(policy.status, 201, policy.body);
  const cycle = JSON.parse(
    await invoke([
      "host",
      "--config",
      config,
      "run",
      "--workspace",
      workspace,
      "--agent",
      "codex",
      "--once",
    ]),
  );
  assert.equal(cycle.snapshots_reported, 1);
  const snapshots = JSON.parse(await invoke(["list"]));
  assert.equal(snapshots.length, 1);
  const request = async () => {
    const rpc = JSON.parse(
      await invoke(
        ["mcp", "--workspace", workspace, "--host-config", config],
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "request_restore",
            arguments: { snapshot: snapshots[0].id, file: "fixture.txt" },
          },
        }) + "\n",
      ),
    );
    assert.equal(rpc.result.isError, undefined, JSON.stringify(rpc.result));
    return JSON.parse(rpc.result.content[0].text);
  };
  writeFileSync(file, "changed");
  const approved = await request();
  const preview = JSON.parse(
    await invoke([
      "host",
      "--config",
      config,
      "review-restore",
      approved.local_request_id,
    ]),
  );
  assert.match(preview.changes[0].preview, /changed/);
  assert.match(preview.changes[0].preview, /4821/);
  const decision = await human(
    `restores/${approved.server_request_id}/decision`,
    {
      decision: "approve",
      diffDigest: approved.diff_digest,
      reviewedLocalDiff: true,
    },
  );
  assert.equal(decision.status, 200, decision.body);
  await invoke([
    "host",
    "--config",
    config,
    "execute-restore",
    approved.local_request_id,
  ]);
  assert.equal(readFileSync(file, "utf8"), "4821");
  await invoke(
    ["host", "--config", config, "execute-restore", approved.local_request_id],
    "",
    false,
  );
  writeFileSync(file, "denied remains");
  const denied = await request();
  const denial = await human(`restores/${denied.server_request_id}/decision`, {
    decision: "deny",
    diffDigest: denied.diff_digest,
    reviewedLocalDiff: false,
  });
  assert.equal(denial.status, 200, denial.body);
  await invoke(
    ["host", "--config", config, "execute-restore", denied.local_request_id],
    "",
    false,
  );
  assert.equal(readFileSync(file, "utf8"), "denied remains");
}
