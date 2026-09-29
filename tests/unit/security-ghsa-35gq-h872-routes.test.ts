import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Route-level regression tests for GHSA-h872-cmwf-8q7v and GHSA-35gq-52m5-wgw2.
 *
 * GHSA-h872: `/api/auth/login` and `/api/cli/connect` check the lockout before an awaited
 * bcrypt compare and record the failure after it, so a concurrent burst from one peer all
 * passes the check against the same stale count. The burst gets more guesses than the
 * lockout threshold allows, and a correct guess late in the burst still logs in.
 *
 * GHSA-35gq: a `write`-scoped access token could create or change an API key, give it the
 * `manage` scope, and use that key to reach admin-only routes such as token mint.
 */

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-ghsa-35gq-h872-"));
process.env.DATA_DIR = TEST_DATA_DIR;
process.env.DISABLE_SQLITE_AUTO_BACKUP = "true";
process.env.JWT_SECRET = "test-jwt-secret-ghsa-h872";
const ORIGINAL_STAMP_TOKEN = process.env.OMNIROUTE_PEER_STAMP_TOKEN;
process.env.OMNIROUTE_PEER_STAMP_TOKEN = "test-peer-stamp-ghsa-h872";
const ORIGINAL_INITIAL_PASSWORD = process.env.INITIAL_PASSWORD;
const PASSWORD = "correct-horse-battery-staple-9f3";
process.env.INITIAL_PASSWORD = PASSWORD;

const core = await import("../../src/lib/db/core.ts");
const at = await import("../../src/lib/db/accessTokens.ts");
const loginRoute = await import("../../src/app/api/auth/login/route.ts");
const connectRoute = await import("../../src/app/api/cli/connect/route.ts");
const { resetLoginGuardForTests, LOGIN_GUARD_TUNABLES } =
  await import("../../src/server/auth/loginGuard.ts");
const { requireManagementAuth } = await import("../../src/lib/api/requireManagementAuth.ts");

const originalGetCookieStore = loginRoute.authRouteInternals.getCookieStore;
const BURST = LOGIN_GUARD_TUNABLES.FAILURE_THRESHOLD + 1;

test.beforeEach(() => {
  resetLoginGuardForTests();
  loginRoute.authRouteInternals.getCookieStore = async () => ({ set() {} }) as never;
});

test.after(() => {
  loginRoute.authRouteInternals.getCookieStore = originalGetCookieStore;
  resetLoginGuardForTests();
  core.resetDbInstance();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  if (ORIGINAL_STAMP_TOKEN === undefined) delete process.env.OMNIROUTE_PEER_STAMP_TOKEN;
  else process.env.OMNIROUTE_PEER_STAMP_TOKEN = ORIGINAL_STAMP_TOKEN;
  if (ORIGINAL_INITIAL_PASSWORD === undefined) delete process.env.INITIAL_PASSWORD;
  else process.env.INITIAL_PASSWORD = ORIGINAL_INITIAL_PASSWORD;
});

function postFrom(peer: string, url: string, body: Record<string, unknown>): Request {
  return new Request(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": peer,
      "x-omniroute-peer-locality": "remote",
      "x-omniroute-trusted-peer-ip": peer,
    },
    body: JSON.stringify(body),
  });
}

// Wrong guesses first, the correct password last: an attacker's burst that happens to
// contain the right password after the threshold has been spent.
function burstPasswords(): string[] {
  return [...Array.from({ length: BURST - 1 }, (_, i) => `wrong-guess-${i}`), PASSWORD];
}

test("login: a concurrent burst cannot guess past the lockout threshold (GHSA-h872)", async () => {
  const peer = "203.0.113.10";
  // Warm-up: persist the password hash, then clear this peer's attempt state.
  const warm = await loginRoute.POST(
    postFrom(peer, "http://localhost/api/auth/login", { password: PASSWORD }) as never
  );
  assert.equal(warm.status, 200);

  const statuses = (
    await Promise.all(
      burstPasswords().map((password) =>
        loginRoute.POST(postFrom(peer, "http://localhost/api/auth/login", { password }) as never)
      )
    )
  ).map((r) => r.status);

  const verified = statuses.filter((s) => s === 401 || s === 200).length;
  assert.notEqual(statuses.at(-1), 200, `correct guess #${BURST} logged in: ${statuses}`);
  assert.ok(
    verified <= LOGIN_GUARD_TUNABLES.FAILURE_THRESHOLD,
    `${verified} password checks answered for one peer: ${statuses}`
  );
});

test("cli/connect: a concurrent burst cannot mint an admin token past the threshold (GHSA-h872)", async () => {
  const peer = "203.0.113.11";
  const statuses = (
    await Promise.all(
      burstPasswords().map((password) =>
        connectRoute.POST(
          postFrom(peer, "http://localhost/api/cli/connect", {
            password,
            name: "burst-cli",
          }) as never
        )
      )
    )
  ).map((r) => r.status);

  assert.ok(
    statuses.at(-1) !== 200 && statuses.at(-1) !== 201,
    `correct guess #${BURST} minted a token: ${statuses}`
  );
});

function authed(method: string, pathname: string, token: string): Request {
  return new Request(`http://localhost:20128${pathname}`, {
    method,
    headers: { authorization: `Bearer ${token}` },
  });
}

test("a write token cannot create, change or reveal API keys (GHSA-35gq)", async () => {
  const { secret } = at.createAccessToken({ name: "write-tok", scope: "write" });
  assert.equal((await requireManagementAuth(authed("POST", "/api/keys", secret)))?.status, 403);
  assert.equal(
    (await requireManagementAuth(authed("PATCH", "/api/keys/abc", secret)))?.status,
    403
  );
  assert.equal(
    (await requireManagementAuth(authed("GET", "/api/keys/abc/reveal", secret)))?.status,
    403
  );
  // Listing keys stays available to a lower-scoped token.
  assert.equal(await requireManagementAuth(authed("GET", "/api/keys", secret)), null);
});
