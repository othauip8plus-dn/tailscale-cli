import { describe, expect, it } from "vitest";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  loadConfigFile,
  maskSecret,
  resolveAuth,
  resolveConfig,
  resolveCredential,
} from "../src/core.js";

describe("credential resolution", () => {
  it("prefers explicit credential and masks it", () => {
    const result = resolveCredential({
      TS_CLIENT_SECRET: "tskey-client-abcdefghijklmnop",
      OTHER: "tskey-client-secondary",
    });
    expect(result.found).toBe(true);
    expect(result.source).toBe("TS_CLIENT_SECRET");
    expect(result.masked).toBe("tskey…nop");
    expect(result.candidates).toEqual(["OTHER"]);
  });

  it("rejects ambiguous environment scan", () => {
    const result = resolveCredential({
      A: "tskey-client-one",
      B: "tskey-client-two",
    });
    expect(result.found).toBe(false);
    expect(result.error).toBe("MULTIPLE_CREDENTIALS");
  });

  it("returns a masked value without exposing the secret", () => {
    expect(maskSecret("super-secret-value")).toBe("super…lue");
  });

  it("honors TS_CREDENTIAL_ENV as the explicit trust credential selector", () => {
    const result = resolveCredential({
      TS_CREDENTIAL_ENV: "CI_TAILSCALE_TRUST",
      CI_TAILSCALE_TRUST: "tskey-client-abc123-wxyz9876qwer",
    });
    expect(result.found).toBe(true);
    expect(result.source).toBe("CI_TAILSCALE_TRUST");
    expect(result.masked).toBe("tskey…wer");
  });

  it("lets TS_CREDENTIAL_ENV beat TS_CLIENT_SECRET and the ambient scan", () => {
    const result = resolveCredential({
      TS_CREDENTIAL_ENV: "CI_TAILSCALE_TRUST",
      CI_TAILSCALE_TRUST: "tskey-client-abc123-wxyz9876qwer",
      TS_CLIENT_SECRET: "tskey-client-other456-lmnop7890qwer",
      OTHER: "tskey-client-secondary",
    });
    expect(result.found).toBe(true);
    expect(result.source).toBe("CI_TAILSCALE_TRUST");
  });

  it("reports CREDENTIAL_ENV_MISSING when the selected env is not set", () => {
    const result = resolveCredential({
      TS_CREDENTIAL_ENV: "CI_TAILSCALE_TRUST",
      OTHER: "tskey-client-secondary",
    });
    expect(result.found).toBe(false);
    expect(result.error).toBe("CREDENTIAL_ENV_MISSING");
    expect(result.candidates).toEqual(["CI_TAILSCALE_TRUST"]);
  });

  it("reports CREDENTIAL_FORMAT_UNSUPPORTED for a selected env without a trust credential", () => {
    const result = resolveCredential({
      TS_CREDENTIAL_ENV: "CI_TAILSCALE_TRUST",
      CI_TAILSCALE_TRUST: "tskey-api-xxx",
    });
    expect(result.found).toBe(false);
    expect(result.error).toBe("CREDENTIAL_FORMAT_UNSUPPORTED");
  });
});

describe("unified auth resolution (manifest precedence)", () => {
  it("resolves TS_AUTH_KEY first", () => {
    const result = resolveAuth({
      TS_AUTH_KEY: "tskey-auth-abc",
      TS_CLIENT_SECRET: "tskey-client-abcdefghijklmnop",
    });
    expect(result.found).toBe(true);
    if (result.auth?.kind !== "node-auth-key")
      throw new Error("expected auth key");
    expect(result.auth.source).toBe("TS_AUTH_KEY");
    expect(result.auth.masked).not.toBe("tskey-auth-abc");
  });

  it("resolves the trust credential before OAuth/access-token/api-key", () => {
    const result = resolveAuth({
      TS_CLIENT_SECRET: "tskey-client-abcdefghijklmnop",
      TS_ACCESS_TOKEN: "tskey-xyz",
      TS_API_KEY: "tskey-api",
    });
    if (result.auth?.kind !== "oauth-trust")
      throw new Error("expected oauth-trust");
    expect(result.auth.source).toBe("TS_CLIENT_SECRET");
    expect(result.auth.masked).toBe("tskey…nop");
  });

  it("resolves the OAuth client pair after the trust credential", () => {
    const result = resolveAuth({
      TS_OAUTH_CLIENT_ID: "client-1",
      TS_OAUTH_CLIENT_SECRET: "secret-1",
      TS_ACCESS_TOKEN: "tskey-xyz",
    });
    if (result.auth?.kind !== "oauth-pair")
      throw new Error("expected oauth-pair");
    expect(result.auth.clientId).toBe("client-1");
  });

  it("resolves the bearer access token before the API key", () => {
    const access = resolveAuth({
      TS_ACCESS_TOKEN: "tskey-access-vlong",
      TS_API_KEY: "tskey-api-key-long",
    });
    if (access.auth?.kind !== "bearer") throw new Error("expected bearer");
    expect(access.auth.source).toBe("TS_ACCESS_TOKEN");
    const api = resolveAuth({ TS_API_KEY: "tskey-api-key-long" });
    if (api.auth?.kind !== "api-key") throw new Error("expected api-key");
    expect(api.auth.source).toBe("TS_API_KEY");
  });

  it("reports ambiguous trust environments instead of guessing", () => {
    const result = resolveAuth({
      A: "tskey-client-one",
      B: "tskey-client-two",
    });
    expect(result.found).toBe(false);
    expect(result.error).toBe("MULTIPLE_CREDENTIALS");
  });

  it("reports not found when nothing is configured", () => {
    const result = resolveAuth({});
    expect(result.found).toBe(false);
    expect(result.error).toBe("CREDENTIAL_NOT_FOUND");
  });
});

describe("config resolution", () => {
  it("uses container defaults", () => {
    const config = resolveConfig({
      CONTAINER: "1",
      TS_HOSTNAME: "My App",
      TS_TAGS: "prod,web",
    });
    expect(config.profile).toBe("container");
    expect(config.hostname).toBe("my-app");
    expect(config.tags).toEqual(["prod", "web"]);
    expect(config.ephemeral).toBe(true);
    expect(config.acceptRoutes).toBe(false);
  });

  it("defaults ssh, preauthorized and accept-dns to true when env is absent", () => {
    const config = resolveConfig({ CI: "true", TS_HOSTNAME: "node-a" });
    expect(config.ssh).toBe(true);
    expect(config.preauthorized).toBe(true);
    expect(config.acceptDns).toBe(true);
    expect(config.keyExpiry).toBe("max");
  });

  it("defaults reusable + warns for long-lived vm profiles", () => {
    const config = resolveConfig({
      TS_PROFILE: "vm",
      TS_HOSTNAME: "web-01",
      TS_TAGS: "prod",
    });
    expect(config.reusable).toBe(true);
    expect(config.warnings).toContain(
      "REUSABLE_KEY_DEFAULTED: auth key created for this long-lived node is reusable until it expires",
    );
  });

  it("appends a run id to CI hostnames when TS_HOSTNAME is absent", () => {
    const config = resolveConfig({
      CI: "true",
      GITHUB_RUN_ID: "98765",
      TS_TAGS: "ci",
    });
    expect(config.hostname.endsWith("-98765")).toBe(true);
    expect(config.hostname.length).toBeLessThanOrEqual(63);
    expect(config.source.hostname).toBe("os.hostname+run");
  });
});

describe("config file loading", () => {
  it("returns undefined when no config file is found", () => {
    const result = loadConfigFile("/nonexistent/path/config.json");
    expect(result).toBeUndefined();
  });

  it("returns undefined for invalid JSON", () => {
    const result = loadConfigFile("/dev/null");
    expect(result).toBeUndefined();
  });

  it("parses JSONC comments, trailing commas and values containing //", () => {
    const path = join(tmpdir(), `core-config-${Date.now()}.jsonc`);
    writeFileSync(
      path,
      [
        "{",
        '  "hostname": "https://example.com/x", // URL with // must survive',
        '  "tailnet": "my-tailnet",',
        "  // trailing comma below",
        '  "ssh": true,',
        "}",
      ].join("\n"),
      "utf8",
    );
    try {
      const result = loadConfigFile(path);
      expect(result?.config.hostname).toBe("https://example.com/x");
      expect(result?.config.tailnet).toBe("my-tailnet");
      expect(result?.config.ssh).toBe(true);
    } finally {
      rmSync(path, { force: true });
    }
  });

  it("falls back to strict JSON parsing for .json configs", () => {
    const path = join(tmpdir(), `core-config-${Date.now()}.json`);
    writeFileSync(
      path,
      JSON.stringify({
        clientSecret: "tskey-client-secret-123",
        tagOwner: ["tag:a"],
      }),
      "utf8",
    );
    try {
      const result = loadConfigFile(path);
      expect(result?.config.clientSecret).toBe("tskey-client-secret-123");
      expect(result?.config.tagOwner).toEqual(["tag:a"]);
    } finally {
      rmSync(path, { force: true });
    }
  });
});
