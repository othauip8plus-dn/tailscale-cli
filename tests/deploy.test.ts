import { describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  resolveKeyExpiry,
  resolveKeyExpiryPlan,
  parseExposure,
  resolveExposures,
  ensureFunnelReadiness,
  resolveTags,
  currentUsername,
  runFunnelWithAttrRetry,
} from "../src/deploy.js";
import { funnelCovered } from "../src/policy.js";
import type { ResolvedConfig } from "../src/types.js";

const readinessConfig: ResolvedConfig = {
  profile: "funnel-app",
  tailnet: "-",
  hostname: "node-a",
  tags: ["web"],
  ssh: true,
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

function jsonResponse(body: unknown, status = 200): Response {
  const headers = new Headers({ "content-type": "application/json" });
  if (body && typeof body === "object") headers.set("etag", '"e1"');
  return new Response(JSON.stringify(body), { status, headers });
}

describe("deploy funnel readiness pre-check (item A)", () => {
  it("refuses to run funnel when the attribute is missing and --apply-policy is absent", async () => {
    vi.stubEnv("TS_API_KEY", "tskey-api-test-key");
    vi.stubEnv("TS_CLIENT_SECRET", "");
    const fetcher = vi.fn(async (_input: RequestInfo | URL) =>
      jsonResponse({ nodeAttrs: [] }),
    );
    vi.stubGlobal("fetch", fetcher);
    try {
      await expect(
        ensureFunnelReadiness(readinessConfig, ["web"], {
          yes: true,
          applyPolicy: false,
        }),
      ).rejects.toThrow("FUNNEL_ATTR_REQUIRED");
      expect(fetcher).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
      vi.unstubAllEnvs();
    }
  });

  it("auto-provisions the funnel attribute before funnel runs when --apply-policy is passed", async () => {
    vi.stubEnv("TS_API_KEY", "tskey-api-test-key");
    vi.stubEnv("TS_CLIENT_SECRET", "");
    const basePolicy = { nodeAttrs: [] };
    const provisionedPolicy = {
      nodeAttrs: [{ target: ["tag:web"], attr: ["funnel"] }],
    };
    const calls = vi
      .fn()
      .mockReturnValueOnce(jsonResponse(basePolicy))
      .mockReturnValueOnce(jsonResponse(basePolicy))
      .mockReturnValueOnce(
        new Response('{\n  "nodeAttrs": []\n}', {
          status: 200,
          headers: { "content-type": "application/hujson", etag: '"e2"' },
        }),
      )
      .mockReturnValueOnce(jsonResponse({}))
      .mockReturnValueOnce(jsonResponse(provisionedPolicy))
      .mockReturnValueOnce(jsonResponse(provisionedPolicy));
    const fetcher = vi.fn(async (_input: RequestInfo | URL) => calls());
    vi.stubGlobal("fetch", fetcher);

    const workDir = mkdtempSync(join(tmpdir(), "tscli-policy-"));
    const previousCwd = process.cwd();
    process.chdir(workDir);
    try {
      const warnings = await ensureFunnelReadiness(readinessConfig, ["web"], {
        yes: true,
        applyPolicy: true,
      });
      expect(warnings.join("\n")).toContain("PROVISIONED_FUNNEL");
      expect(fetcher.mock.calls.length).toBe(6);

      const backs = readdirSync(workDir).filter((name) =>
        name.startsWith("policy.provision-"),
      );
      expect(backs.length).toBe(1);
      const backupContent = readFileSync(join(workDir, backs[0]!), "utf8");
      expect(backupContent).toBe('{\n  "nodeAttrs": []\n}');
      expect(backupContent).not.toContain("funnel");
      expect(warnings.join("\n")).toContain(
        `POLICY_BACKUP: pre-write policy saved to ${backs[0]}`,
      );
    } finally {
      process.chdir(previousCwd);
      rmSync(workDir, { recursive: true, force: true });
      vi.unstubAllGlobals();
      vi.unstubAllEnvs();
    }
  });

  it("warns FUNNEL_ATTR_UNVERIFIABLE without a policy read scope and lets funnel proceed", async () => {
    vi.stubEnv("TS_API_KEY", "tskey-api-test-key");
    vi.stubEnv("TS_CLIENT_SECRET", "");
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async (_input: RequestInfo | URL) =>
          new Response(
            JSON.stringify({ message: "scope denied: policy_file:read" }),
            {
              status: 403,
              headers: { "content-type": "application/json" },
            },
          ),
      ),
    );
    try {
      const warnings = await ensureFunnelReadiness(readinessConfig, ["web"], {
        yes: true,
        applyPolicy: true,
      });
      expect(warnings.join("\n")).toContain("FUNNEL_ATTR_UNVERIFIABLE");
    } finally {
      vi.unstubAllGlobals();
      vi.unstubAllEnvs();
    }
  });
});

describe("key expiry resolution", () => {
  it("maps max and the default to the documented 90-day ceiling", () => {
    expect(resolveKeyExpiry("max")).toBe(90 * 24 * 60 * 60);
    expect(resolveKeyExpiry("")).toBe(90 * 24 * 60 * 60);
  });

  it("caps unlimited at the documented 90-day ceiling", () => {
    expect(resolveKeyExpiry("unlimited")).toBe(90 * 24 * 60 * 60);
    expect(resolveKeyExpiry("UNLIMITED")).toBe(90 * 24 * 60 * 60);
  });

  it("accepts explicit seconds", () => {
    expect(resolveKeyExpiry("3600")).toBe(3600);
    expect(resolveKeyExpiry("90")).toBe(90);
  });

  it("rejects invalid values", () => {
    expect(() => resolveKeyExpiry("soon")).toThrow("KEY_EXPIRY_INVALID");
    expect(() => resolveKeyExpiry("-5")).toThrow("KEY_EXPIRY_INVALID");
    expect(() => resolveKeyExpiry("0")).toThrow("KEY_EXPIRY_INVALID");
    expect(() => resolveKeyExpiry("1.5x")).toThrow("KEY_EXPIRY_INVALID");
  });
});

describe("key expiry plan (documented ceiling, not a discovered server max)", () => {
  it("warns KEY_EXPIRY_MAX only for the default, not for an explicit max", () => {
    const plan = resolveKeyExpiryPlan("max", "default");
    expect(plan.seconds).toBe(90 * 24 * 60 * 60);
    expect(plan.warnings.join("\n")).toContain("KEY_EXPIRY_MAX");
    expect(plan.warnings.join("\n")).toContain("documented 90-day");
    const explicit = resolveKeyExpiryPlan("max", "TS_KEY_EXPIRY");
    expect(explicit.seconds).toBe(90 * 24 * 60 * 60);
    expect(explicit.warnings).toEqual([]);
  });

  it("warns that unlimited is capped at the documented ceiling", () => {
    const plan = resolveKeyExpiryPlan("unlimited", "TS_KEY_EXPIRY");
    expect(plan.seconds).toBe(90 * 24 * 60 * 60);
    expect(plan.warnings.join("\n")).toContain("KEY_EXPIRY_UNLIMITED");
  });

  it("clamps explicit seconds above the ceiling with a warning", () => {
    const plan = resolveKeyExpiryPlan("999999999", "TS_KEY_EXPIRY");
    expect(plan.seconds).toBe(90 * 24 * 60 * 60);
    expect(plan.warnings.join("\n")).toContain("KEY_EXPIRY_CLAMPED");
  });

  it("passes in-range seconds through untouched", () => {
    const plan = resolveKeyExpiryPlan("3600", "TS_KEY_EXPIRY");
    expect(plan.seconds).toBe(3600);
    expect(plan.warnings).toEqual([]);
  });
});

describe("funnel attribute coverage", () => {
  const policy = {
    nodeAttrs: [
      { target: ["tag:web"], attr: ["funnel"] },
      { target: ["tag:ops"], attr: ["another"] },
    ],
  };

  it("reports covered when every requested tag has the funnel attribute", () => {
    expect(funnelCovered(policy, ["web"])).toBe(true);
  });

  it("reports missing when any requested tag lacks the attribute", () => {
    expect(funnelCovered(policy, ["web", "ops"])).toBe(false);
    expect(funnelCovered(policy, ["unlisted"])).toBe(false);
  });

  it("falls back to autogroup:member for untagged nodes", () => {
    expect(funnelCovered(policy, [])).toBe(false);
    expect(
      funnelCovered(
        {
          nodeAttrs: [{ target: ["autogroup:member"], attr: ["funnel"] }],
        },
        [],
      ),
    ).toBe(true);
  });
});

describe("exposure parsing", () => {
  it("turns a port into a loopback HTTP target", () => {
    expect(parseExposure("3000")).toEqual({
      target: "http://127.0.0.1:3000",
      public: false,
      path: undefined,
      https: 3000,
    });
  });

  it("accepts localhost and paths", () => {
    expect(parseExposure("localhost:8080#api")).toEqual({
      target: "http://localhost:8080",
      public: false,
      path: "/api",
      https: 8080,
    });
  });

  it("maps a public port to a different local target", () => {
    expect(parseExposure("443=8443")).toEqual({
      target: "http://127.0.0.1:8443",
      public: false,
      https: 443,
    });
    expect(parseExposure("8443#/api=3001")).toEqual({
      target: "http://127.0.0.1:3001",
      public: false,
      path: "/api",
      https: 8443,
    });
  });

  it("rejects invalid public ports", () => {
    expect(() => parseExposure("0=8443")).toThrow("EXPOSE_INVALID_PUBLIC_PORT");
    expect(() => parseExposure("70000=8443")).toThrow(
      "EXPOSE_INVALID_PUBLIC_PORT",
    );
  });

  it("rejects unsupported targets", () => {
    expect(() => parseExposure("ftp://example.com")).toThrow(
      "EXPOSE_INVALID_TARGET",
    );
  });

  it("marks funnel exposures as public", () => {
    expect(resolveExposures(["3000"], true)[0]?.public).toBe(true);
  });
});

describe("runFunnelWithAttrRetry (funnel propagation retry)", () => {
  const matchingError = () =>
    new Error(
      'funnel is not available on this node because "funnel" node attribute is not set',
    );

  it("does not retry when funnel succeeds immediately", async () => {
    const run = vi.fn(async () => {});
    await runFunnelWithAttrRetry(run, { retryDelayMs: 0 });
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("retries a matching failure until funnel succeeds", async () => {
    const run = vi
      .fn<() => Promise<void>>()
      .mockRejectedValueOnce(matchingError())
      .mockResolvedValueOnce();
    await runFunnelWithAttrRetry(run, { retryDelayMs: 0 });
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("throws FUNNEL_ATTR_REQUIRED when every retry fails with a matching error", async () => {
    const run = vi.fn(async () => {
      throw matchingError();
    });
    await expect(
      runFunnelWithAttrRetry(run, { retryDelayMs: 0, attempts: 2 }),
    ).rejects.toThrow("FUNNEL_ATTR_REQUIRED");
    expect(run).toHaveBeenCalledTimes(3);
  });

  it("rethrows a non-matching final retry failure verbatim instead of swallowing it", async () => {
    const run = vi
      .fn<() => Promise<void>>()
      .mockRejectedValueOnce(matchingError())
      .mockRejectedValue(new Error("EACCES: permission denied"));
    await expect(
      runFunnelWithAttrRetry(run, { retryDelayMs: 0 }),
    ).rejects.toThrow(/^EACCES: permission denied$/);
    expect(run).toHaveBeenCalledTimes(5);
  });

  it("rethrows non-propagation failures immediately without retrying", async () => {
    const run = vi.fn(async () => {
      throw new Error("port 443 already in use");
    });
    await expect(runFunnelWithAttrRetry(run)).rejects.toThrow("already in use");
    expect(run).toHaveBeenCalledTimes(1);
  });
});

describe("resolveTags auto-tagging", () => {
  it("uses explicitly configured tags when present and ssh is false", () => {
    const res = resolveTags({
      ...readinessConfig,
      ssh: false,
      tags: ["tag:custom"],
    });
    expect(res).toEqual({ tags: ["tag:custom"], autoTagged: false });
  });

  it("derives deterministic tag when tags are empty even in dev profile when ssh is false", () => {
    vi.stubEnv("GITHUB_REPOSITORY", "");
    vi.stubEnv("GITLAB_PROJECT_PATH", "");
    vi.stubEnv("CI_PROJECT_PATH", "");
    vi.stubEnv("TS_TAG_BASE", "");
    try {
      const res = resolveTags({
        ...readinessConfig,
        ssh: false,
        profile: "dev",
        tags: [],
        hostname: "my-dev-box",
      });
      expect(res).toEqual({ tags: ["tag:my-dev-box"], autoTagged: true });
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("automatically appends tag:sshwhoami-<username> when ssh is true", () => {
    vi.stubEnv("GITHUB_REPOSITORY", "");
    vi.stubEnv("GITLAB_PROJECT_PATH", "");
    vi.stubEnv("CI_PROJECT_PATH", "");
    vi.stubEnv("TS_TAG_BASE", "");
    try {
      const userSlug =
        currentUsername()
          .toLowerCase()
          .replace(/[^a-z0-9-]+/g, "-")
          .replace(/^-+|-+$/g, "") || "user";
      const res = resolveTags({
        ...readinessConfig,
        ssh: true,
        profile: "dev",
        tags: [],
        hostname: "my-dev-box",
      });
      expect(res.tags).toEqual(["tag:my-dev-box", `tag:sshwhoami-${userSlug}`]);
      expect(res.autoTagged).toBe(true);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("derives tag from GITHUB_REPOSITORY when present in environment", () => {
    vi.stubEnv("GITHUB_REPOSITORY", "my-org/my-repo");
    try {
      const res = resolveTags({
        ...readinessConfig,
        ssh: false,
        profile: "dev",
        tags: [],
        hostname: "my-dev-box",
      });
      expect(res.tags).toEqual(["tag:my-org-my-repo"]);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
