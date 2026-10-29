import test from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { api, ClientError, logout } from "../src/lib/client";
import { SnapshotComparison } from "../src/components/snapshot-comparison";

test("comparison renders retained selections when the latest-200 poll evicts rows", () => {
  const first = {
    id: "first",
    body: { fileCount: 3, totalBytes: 100, manifestDigest: "a".repeat(64) },
  };
  const second = { ...first, id: "second" };
  const selected = [first, second];
  const latestPoll = Array.from({ length: 200 }, (_, i) => ({
    ...first,
    id: `new-${i}`,
  }));
  assert.ok(selected.every((s) => !latestPoll.some((row) => row.id === s.id)));
  const html = renderToStaticMarkup(
    <SnapshotComparison snapshots={selected} />,
  );
  assert.match(html, /Snapshot metadata comparison/);
  assert.match(html, /first/);
  assert.match(html, /second/);
  assert.equal(
    renderToStaticMarkup(<SnapshotComparison snapshots={[first, undefined]} />),
    "",
  );
  assert.equal(renderToStaticMarkup(<SnapshotComparison snapshots={[]} />), "");
});

test("client preserves 401 status for JSON and non-JSON responses", async (t) => {
  for (const response of [
    Response.json({ error: "Session expired" }, { status: 401 }),
    new Response("Unauthorized", { status: 401 }),
    Response.json(
      { error: "Session expired", issues: [null, { path: false }] },
      { status: 401 },
    ),
  ]) {
    t.mock.method(globalThis, "fetch", async () => response);
    await assert.rejects(
      api("tenants/test/snapshots"),
      (e) => e instanceof ClientError && e.status === 401,
    );
  }
});

test("logout always clears local session even if the server rejects or is offline", async (t) => {
  for (const fetcher of [
    async () => Response.json({ ok: true }),
    async () => Response.json({ error: "Session expired" }, { status: 401 }),
    async () => {
      throw new TypeError("Network unavailable");
    },
  ]) {
    t.mock.method(globalThis, "fetch", fetcher);
    let cleared = 0;
    await logout(() => {
      cleared++;
    }).catch(() => {});
    assert.equal(cleared, 1);
  }
});

test("restore evidence renders skipped separately and never counts incomplete reports as passed", async () => {
  const { ProbeResultBadge } = await import("../src/components/probe-result");
  const { evidenceOutcome } = await import("../src/lib/evidence");
  const skipped = {
    outcome: "not_run" as const,
    reasonCode: "credentials_unavailable",
  };
  const html = renderToStaticMarkup(<ProbeResultBadge probe={skipped} />);
  assert.match(html, /skipped \(not run\)/);
  assert.match(html, /credentials unavailable/);
  assert.doesNotMatch(html, /succeeded|failed/);
  assert.equal(
    evidenceOutcome({ agents: [{ outcome: "passed" }], mcps: [skipped] }),
    "not_run",
  );
  assert.equal(
    evidenceOutcome({ agents: [{ passed: true }], mcps: [] }),
    "passed",
  );
  assert.equal(
    evidenceOutcome({ agents: [{ passed: false }], mcps: [skipped] }),
    "failed",
  );
  assert.equal(evidenceOutcome({ agents: [], mcps: [] }), "not_run");
});

test("file-content evidence explicitly excludes Git recovery and legacy scope stays unknown", async () => {
  const { RestoreProbeScope } = await import("../src/components/probe-result");
  assert.match(
    renderToStaticMarkup(<RestoreProbeScope scope="file-content" />),
    /Git refs and configuration were not restored/,
  );
  assert.match(
    renderToStaticMarkup(<RestoreProbeScope />),
    /scope was not reported/,
  );
});
