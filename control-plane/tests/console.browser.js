// Run the default function in a browser on the local signed-out console.
// Fetch is replaced with metadata fixtures; no database or credentials are used.
export default async function consoleRegression() {
  const originalFetch = window.fetch;
  const originalInterval = window.setInterval;
  const originalClearInterval = window.clearInterval;
  let tick;
  let expired = false;
  let evicted = false;
  let logoutFails = false;
  const assert = (condition, message) => {
    if (!condition) throw new Error(message);
  };
  const wait = async (condition) => {
    for (let i = 0; i < 100; i++) {
      if (condition()) return;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error("Timed out waiting for console render");
  };
  const snapshots = (evicted) =>
    Array.from({ length: evicted ? 200 : 2 }, (_, i) => ({
      id: `${evicted ? "new" : "selected"}-${i}`,
      host_id: "host",
      created_at: "2026-10-29T00:00:00Z",
      body: {
        agent: "codex",
        sessionId: "session",
        manifestDigest: "a".repeat(64),
        fileCount: i + 1,
        totalBytes: 100,
        capturedAt: "2026-10-29T00:00:00Z",
        status: "succeeded",
      },
    }));
  window.setInterval = (callback, delay, ...args) => {
    if (delay === 15000) {
      tick = callback;
      return 987654;
    }
    return originalInterval(callback, delay, ...args);
  };
  window.clearInterval = (id) => {
    if (id === 987654) tick = undefined;
    else originalClearInterval(id);
  };
  window.fetch = async (input) => {
    const path = String(input);
    if (path.endsWith("auth/logout"))
      return Response.json(
        logoutFails ? { error: "Session expired" } : { ok: true },
        { status: logoutFails ? 401 : 200 },
      );
    if (path.endsWith("auth/login")) {
      expired = false;
      return Response.json({ ok: true });
    }
    if (expired)
      return Response.json({ error: "Session expired" }, { status: 401 });
    if (path.endsWith("/me"))
      return Response.json({
        tenants: [{ id: "tenant", name: "Browser regression", role: "admin" }],
        hostTransport: "development-loopback",
      });
    if (path.endsWith("/snapshots")) return Response.json(snapshots(evicted));
    return Response.json([]);
  };
  const login = async () => {
    document.querySelector('input[name="email"]').value = "test@example.test";
    document.querySelector('input[name="password"]').value = "fixture-password";
    document.querySelector("form").requestSubmit();
    await wait(
      () =>
        document.querySelectorAll('input[aria-label^="Compare snapshot"]')
          .length > 0 && tick,
    );
  };
  const compare = async () => {
    const boxes = document.querySelectorAll(
      'input[aria-label^="Compare snapshot"]',
    );
    boxes[0].click();
    await new Promise((resolve) => setTimeout(resolve, 0));
    boxes[1].click();
    await wait(() =>
      document.body.innerText.includes("Snapshot metadata comparison"),
    );
  };
  const signOut = () =>
    [...document.querySelectorAll("button")]
      .find((b) => b.textContent === "Sign out")
      .click();
  try {
    await login();
    await compare();
    evicted = true;
    await tick();
    await wait(
      () =>
        document.querySelectorAll('input[aria-label^="Compare snapshot new-"]')
          .length === 200,
    );
    assert(
      document.body.innerText.includes("Snapshot metadata comparison"),
      "comparison survived eviction",
    );
    assert(
      document.body.innerText.includes("selected-0"),
      "evicted metadata retained",
    );
    expired = true;
    await tick();
    await wait(() => document.querySelector('input[name="email"]'));
    assert(
      !document.body.innerText.includes("Browser regression"),
      "401 clears tenant data",
    );
    evicted = false;
    await login();
    assert(
      !document.body.innerText.includes("Snapshot metadata comparison"),
      "401 clears comparison selections",
    );
    await compare();
    logoutFails = true;
    signOut();
    await wait(() => document.querySelector('input[name="email"]'));
    await login();
    assert(
      !document.body.innerText.includes("Snapshot metadata comparison"),
      "failed logout clears comparison selections",
    );
    assert(
      [...document.querySelectorAll('input[type="checkbox"]')].every(
        (box) => !box.checked,
      ),
      "relogin has no stale selected IDs",
    );
    logoutFails = false;
    signOut();
    await wait(() => document.querySelector('input[name="email"]'));
    return {
      passed: [
        "actual Console render after 200-row eviction",
        "401 poll clears auth and tenant state",
        "relogin clears comparison",
        "rejected logout still clears local state",
      ],
    };
  } finally {
    window.fetch = originalFetch;
    window.setInterval = originalInterval;
    window.clearInterval = originalClearInterval;
  }
}
