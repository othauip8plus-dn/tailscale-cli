import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import {
  generateSampleConfig,
  loadServiceConfig,
  validateServiceConfig,
  resolveUserName,
  maskEnv,
} from "../src/service/config.js";

const tmpDir = resolvePath("/tmp/ts-service-config-test");

describe("service config", () => {
  beforeEach(() => {
    mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("B1-1 loads a valid config with all fields", () => {
    const path = `${tmpDir}/valid.json`;
    writeFileSync(
      path,
      JSON.stringify({
        name: "my-relay",
        description: "test",
        user: "alice",
        workingDir: tmpDir,
        script: "",
        args: ["relay", "--listen", "18888"],
        env: { A: "1" },
        restart: { onFailure: true, delaySeconds: 5, maxRetries: 3 },
      }),
      "utf8",
    );
    const cfg = loadServiceConfig(path);
    expect(cfg.name).toBe("my-relay");
    expect(cfg.user).toBe("alice");
    expect(cfg.workingDir).toBe(tmpDir);
    expect(cfg.args).toEqual(["relay", "--listen", "18888"]);
    expect(cfg.restart.delaySeconds).toBe(5);
  });

  it("B1-2 loads JSONC with comments and trailing commas", () => {
    const path = `${tmpDir}/jsonc.jsonc`;
    const jsonSafeDir = tmpDir.replaceAll("\\", "/");
    writeFileSync(
      path,
      [
        "// comment line",
        "{",
        '  "name": "my-relay", // trailing comment',
        '  "workingDir": "' + jsonSafeDir + '",',
        '  "args": ["relay", "--listen", "18888",],',
        "}",
      ].join("\n"),
      "utf8",
    );
    const cfg = loadServiceConfig(path);
    expect(cfg.name).toBe("my-relay");
    expect(cfg.args).toEqual(["relay", "--listen", "18888"]);
  });

  it("B1-3 rejects an invalid service name", () => {
    expect(() =>
      validateServiceConfig({ name: "my service!" } as never, tmpDir),
    ).toThrow(/SERVICE_NAME_INVALID/);
  });

  it("B1-4 rejects a missing required field", () => {
    expect(() => validateServiceConfig({} as never, tmpDir)).toThrow(
      /SERVICE_CONFIG_MISSING_FIELD: name/,
    );
  });

  it("B1-5 rejects a missing workingDir", () => {
    expect(() =>
      validateServiceConfig(
        { name: "my-relay", workingDir: "/nonexistent" } as never,
        tmpDir,
      ),
    ).toThrow(/SERVICE_WORKDIR_NOT_FOUND/);
  });

  it("B1-6 generates a sample config with the requested name", () => {
    const sample = generateSampleConfig("my-relay");
    expect(sample).toContain('"name": "my-relay"');
    expect(sample).toContain("// .tailsacle-service.jsonc");
  });

  it('B1-7 resolves user "current" to the OS user', () => {
    expect(resolveUserName("current")).toBe(
      process.env.USER ?? process.env.USERNAME,
    );
    expect(resolveUserName("alice")).toBe("alice");
  });

  it("B1-8 masks secret-like env values", () => {
    const masked = maskEnv({
      NODE_ENV: "production",
      TS_CLIENT_SECRET: "tskey-client-abc123",
    });
    expect(masked.NODE_ENV).toBe("production");
    expect(masked.TS_CLIENT_SECRET).toBe("****");
  });

  it("masks secret-named keys even when the value looks opaque", () => {
    const masked = maskEnv({ NODE_ENV: "production", PGPASSWORD: "hunter2" });
    expect(masked.NODE_ENV).toBe("production");
    expect(masked.PGPASSWORD).toBe("****");
  });

  it("throws SERVICE_CONFIG_NOT_FOUND for a missing file", () => {
    expect(() => loadServiceConfig(`${tmpDir}/missing.json`)).toThrow(
      /SERVICE_CONFIG_NOT_FOUND/,
    );
  });

  it("rejects a script path that does not exist", () => {
    expect(() =>
      validateServiceConfig(
        {
          name: "my-relay",
          workingDir: tmpDir,
          script: "/no/such/script.js",
          args: [],
        } as never,
        tmpDir,
      ),
    ).toThrow(/SERVICE_SCRIPT_NOT_FOUND/);
  });

  it("resolves relative workingDir against the config directory", () => {
    const path = `${tmpDir}/rel.json`;
    writeFileSync(
      path,
      JSON.stringify({
        name: "my-relay",
        workingDir: ".",
        args: [],
      }),
      "utf8",
    );
    const cfg = loadServiceConfig(path);
    expect(cfg.workingDir).toBe(tmpDir);
  });

  it("defaults restart policy and env when omitted", () => {
    const path = `${tmpDir}/minimal.json`;
    writeFileSync(
      path,
      JSON.stringify({ name: "my-relay", workingDir: tmpDir, args: [] }),
      "utf8",
    );
    const cfg = loadServiceConfig(path);
    expect(cfg.restart.onFailure).toBe(true);
    expect(cfg.restart.delaySeconds).toBe(5);
    expect(cfg.restart.maxRetries).toBe(10);
    expect(cfg.env).toEqual({});
    expect(existsSync(path)).toBe(true);
  });
});
