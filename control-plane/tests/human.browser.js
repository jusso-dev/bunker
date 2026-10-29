// Evaluate the default function in T3 preview on test-human-browser.sh's URL,
// passing that disposable harness's fixture.json. Uses real HTTP and PostgreSQL.
export default async function humanBrowserRegression(fixture) {
  const originalInterval = window.setInterval;
  const originalClear = window.clearInterval;
  let tick;
  window.setInterval = (callback, delay, ...args) => {
    if (delay === 15000) {
      tick = callback;
      return 987650;
    }
    return originalInterval(callback, delay, ...args);
  };
  window.clearInterval = (id) => {
    if (id === 987650) tick = undefined;
    else originalClear(id);
  };
  const assert = (value, message) => {
    if (!value) throw new Error(message);
  };
  const wait = async (fn, message) => {
    for (let i = 0; i < 200; i++) {
      if (fn()) return;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    throw new Error(message ?? "Timed out waiting for UI");
  };
  const button = (text) =>
    [...document.querySelectorAll("button")].find(
      (b) => b.textContent.trim() === text,
    );
  const click = async (text) => {
    await wait(() => button(text) && !button(text).disabled, `button ${text}`);
    button(text).click();
    await new Promise((r) => setTimeout(r, 0));
  };
  const input = (name, value) => {
    const field = document.querySelector(`input[name="${name}"]`);
    assert(field, `input ${name}`);
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    ).set.call(field, value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const boxes = () => [
    ...document.querySelectorAll('input[aria-label^="Compare snapshot"]'),
  ];
  const selectTenant = async (id) => {
    const select = document.querySelector(".tenant-label select");
    if (select.value === id) return;
    select.value = id;
    select.dispatchEvent(new Event("change", { bubbles: true }));
    await wait(
      () => document.querySelector(".tenant-label select")?.value === id,
    );
  };
  const login = async (email, password) => {
    await wait(() => document.querySelector('input[name="email"]'));
    input("email", email);
    input("password", password);
    await click("Sign in");
    await wait(() => document.querySelector(".tenant-label select"));
    if (
      [...document.querySelector(".tenant-label select").options].some(
        (option) => option.value === fixture.tenant,
      )
    )
      await selectTenant(fixture.tenant);
  };
  const signOut = async () => {
    await click("Sign out");
    await wait(() => document.querySelector('input[name="password"]'));
  };
  const passed = [];
  try {
    await login("admin@browser.example.test", "browser-disposable-password");
    await wait(() => boxes().length === 200 && tick, "first 200 snapshots");
    boxes()[0].click();
    await new Promise((r) => setTimeout(r, 0));
    boxes()[1].click();
    await wait(() =>
      document.body.innerText.includes("Snapshot metadata comparison"),
    );
    const selected = boxes()
      .filter((box) => box.checked)
      .map((box) => box.getAttribute("aria-label"));
    await click("Load more snapshots");
    await wait(() => boxes().length === 205);
    assert(
      selected.every(
        (label) =>
          boxes().find((box) => box.getAttribute("aria-label") === label)
            ?.checked,
      ),
      "selections survive append",
    );
    await tick();
    await wait(() => boxes().length === 205);
    assert(
      selected.every(
        (label) =>
          boxes().find((box) => box.getAttribute("aria-label") === label)
            ?.checked,
      ),
      "selections survive real refresh",
    );
    assert(!button("Load more snapshots"), "end cursor hides load more");
    passed.push(
      "real database 200+5 equal-time pages, append/poll retain selections, end cursor",
    );

    await selectTenant(fixture.other);
    await wait(() => boxes().length === 0);
    assert(
      !document.body.innerText.includes("Snapshot metadata comparison"),
      "tenant switch clears selection",
    );
    await selectTenant(fixture.tenant);
    await wait(() => boxes().length === 200);
    assert(
      !document.getElementById(`snapshot-${fixture.oldSnapshot}`),
      "old snapshot starts outside first page",
    );
    await click("Alerts");
    const link = [...document.querySelectorAll("a")].find(
      (a) => a.textContent.trim() === "Open snapshot",
    );
    assert(link, "snapshot link");
    link.click();
    await wait(() =>
      document.getElementById(`snapshot-${fixture.oldSnapshot}`),
    );
    passed.push(
      "tenant selection isolation and real older snapshot link lookup",
    );

    await click("Administration");
    await wait(() => button("Remove access for viewer@browser.example.test"));
    await click("Remove access for viewer@browser.example.test");
    await wait(
      () =>
        !button("Remove access for viewer@browser.example.test") &&
        document.body.innerText.includes("Tenant access removed."),
    );
    await selectTenant(fixture.tenant);
    await wait(() => button("Remove access for admin@browser.example.test"));
    await click("Remove access for admin@browser.example.test");
    await wait(() =>
      document.body.innerText.includes(
        "Cannot remove the last tenant administrator",
      ),
    );
    passed.push("membership removal UI and last-admin rejection");

    await click("Account");
    await wait(() => button("Load more sessions"));
    await click("Load more sessions");
    await wait(() => document.querySelectorAll(".panel .row").length === 202);
    assert(!button("Load more sessions"), "session pagination ends");
    await click("Revoke session");
    await wait(() => document.body.innerText.includes("Session revoked."));
    await click("Sign out other sessions");
    await wait(() => document.querySelectorAll(".panel .row").length === 1);
    assert(
      /this session/i.test(document.body.innerText),
      "self remains after revoke others",
    );
    input("currentPassword", "incorrect");
    input("newPassword", "browser-replacement-password");
    await click("Change password and sign out");
    await wait(() =>
      document.body.innerText.includes("Current password is incorrect"),
    );
    input("currentPassword", "browser-disposable-password");
    await click("Change password and sign out");
    await wait(() => document.querySelector('input[name="email"]'));
    await login("admin@browser.example.test", "browser-replacement-password");
    await wait(() => boxes().length === 200);
    passed.push(
      "session load/revoke/revoke-others and password current-credential check/signout/relogin",
    );
    await signOut();

    await login("viewer@browser.example.test", "browser-disposable-password");
    await wait(
      () =>
        document.querySelector(".tenant-label select")?.options.length === 0,
    );
    assert(
      !document.body.innerText.includes("Browser lifecycle"),
      "removed user cannot see revoked tenant",
    );
    await click("Account");
    await wait(() => document.body.innerText.includes("Active sessions"));
    await signOut();
    passed.push(
      "removed human retains global account but has no revoked tenant in rendered UI",
    );

    document.querySelector("details").open = true;
    input("token", fixture.recoveryToken);
    input("newPassword", "browser-recovered-password");
    await click("Recover local password");
    await wait(() =>
      document.body.innerText.includes(
        "Password recovered. Sign in with your new password.",
      ),
    );
    await login("recover@browser.example.test", "browser-recovered-password");
    await wait(() => boxes().length === 200);
    await signOut();
    document.querySelector("details").open = true;
    input("token", fixture.recoveryToken);
    input("newPassword", "browser-recovered-again-password");
    await click("Recover local password");
    await wait(() =>
      document.body.innerText.includes("Recovery token invalid or expired"),
    );
    passed.push(
      "operator-issued recovery UI accepts once, signs in with changed credential, rejects replay",
    );
    return { passed };
  } finally {
    window.setInterval = originalInterval;
    window.clearInterval = originalClear;
  }
}
