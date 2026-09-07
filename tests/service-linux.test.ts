import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, rmSync, writeFileSync, existsSync } from "node:fs";

const mockSpawnSync = vi.fn();

vi.mock("node:child_process", () => ({
  spawnSync: (...args: unknown[]) => mockSpawnSync(...args),
}));

import {
  renderUnit,
  unitPathFor,
  detectRelayPorts,
  LinuxServiceManager,
} from "../src/service/linux.js";
import type { ServiceConfig } from "../src/service/types.js";

const fakeHome = "/tmp/ts-service-linux-home";

function config(): ServiceConfig {
  return {
    name: "my-relay",
    description: "test relay",
    user: "alice",
    workingDir: "/work",
    args: ["relay", "--listen", "18888"],
    env: { A: "1", B: "2" },
    restart: { onFailure: true, delaySeconds: 10, maxRetries: 5 },
  };
}

function mockSystemctlSequence(
  calls: Array<{ args: string[]; stdout?: string }>,
) {
  let callIndex = 0;
  mockSpawnSync.mockImplementation((cmd: string, args: string[]) => {
    void cmd;
    void args;
    const entry = calls[callIndex];
    callIndex += 1;
    return entry
      ? { status: 0, stdout: entry.stdout ?? "", stderr: "" }
      : { status: 0, stdout: "", stderr: "" };
  });
}

function systemctlCalls(): Array<{ cmd: string; args: string[] }> {
  return mockSpawnSync.mock.calls.map((c) => ({
    cmd: c[0] as string,
    args: c[1] as string[],
  }));
}

describe.skipIf(process.platform !== "linux")("linux service manager", () => {
  beforeEach(() => {
    mockSpawnSync.mockReset();
    mkdirSync(fakeHome, { recursive: true });
    process.env.HOME = fakeHome;
  });

  afterEach(() => {
    rmSync(fakeHome, { recursive: true, force: true });
  });

  it("B3-1 renders all three unit sections", () => {
    const unit = renderUnit(config());
    expect(unit).toContain("[Unit]");
    expect(unit).toContain("[Service]");
    expect(unit).toContain("[Install]");
  });

  it("B3-2 sets the User field", () => {
    const unit = renderUnit(config());
    expect(unit).toContain("User=alice");
  });

  it("B3-3 renders Environment lines", () => {
    const unit = renderUnit(config());
    expect(unit).toContain("Environment=A=1");
    expect(unit).toContain("Environment=B=2");
  });

  it("B3-4 renders the restart policy", () => {
    const unit = renderUnit(config());
    expect(unit).toContain("Restart=on-failure");
    expect(unit).toContain("RestartSec=10s");
    expect(unit).toContain("StartLimitBurst=5");
  });

  it("B3-5 uses the user unit path with --user", () => {
    expect(unitPathFor("my-relay", { user: true })).toBe(
      `${fakeHome}/.config/systemd/user/my-relay.service`,
    );
  });

  it("B3-6 uses the system unit path by default", () => {
    expect(unitPathFor("my-relay")).toBe(
      "/etc/systemd/system/my-relay.service",
    );
  });

  it("B3-7 sets SyslogIdentifier", () => {
    const unit = renderUnit(config());
    expect(unit).toContain("SyslogIdentifier=my-relay");
  });

  it("B3-8 calls daemon-reload then enable --now in order", async () => {
    mockSystemctlSequence([
      { args: ["daemon-reload"] },
      { args: ["enable", "--now", "my-relay"] },
    ]);
    mockSpawnSync.mockImplementation((_cmd: string, args: string[]) => {
      if (args.includes("show")) {
        return {
          status: 0,
          stdout: [
            "ActiveState=active",
            "SubState=running",
            "MainPID=12345",
            "ExecMainStartTimestamp=2026-08-19T00:00:00Z",
            "NRestarts=2",
            "",
          ].join("\n"),
          stderr: "",
        };
      }
      return { status: 0, stdout: "", stderr: "" };
    });
    const manager = new LinuxServiceManager();
    const result = await manager.install(config(), { user: true });
    const calls = systemctlCalls();
    const flat = calls
      .filter((c) => c.cmd === "systemctl")
      .map((c) => c.args.join(" "));
    expect(flat[0]).toBe("--user daemon-reload");
    expect(flat[1]).toBe("--user enable --now my-relay");
    expect(result.installed).toBe(true);
    expect(result.status).toBe("running");
    expect(result.pid).toBe(12345);
    expect(result.scope).toBe("user");
  });

  it("detects relay ports from --listen and --map args", () => {
    expect(
      detectRelayPorts([
        "relay",
        "--listen",
        "18888",
        "--target",
        "127.0.0.1:19999",
      ]),
    ).toEqual([18888]);
    expect(detectRelayPorts(["relay", "--map", "5432:5433,5434:5435"])).toEqual(
      [5432, 5434],
    );
    expect(detectRelayPorts(["relay", "--listen", "notaport"])).toEqual([]);
  });

  it("throws SERVICE_ALREADY_EXISTS when the unit file exists", async () => {
    mkdirSync(`${fakeHome}/.config/systemd/user`, { recursive: true });
    writeFileSync(`${fakeHome}/.config/systemd/user/my-relay.service`, "x");
    const manager = new LinuxServiceManager();
    await expect(manager.install(config(), { user: true })).rejects.toThrow(
      /SERVICE_ALREADY_EXISTS/,
    );
  });

  it("uninstall removes the unit file and registry entry", async () => {
    mockSystemctlSequence([]);
    mkdirSync(`${fakeHome}/.config/systemd/user`, { recursive: true });
    writeFileSync(`${fakeHome}/.config/systemd/user/my-relay.service`, "x");
    const manager = new LinuxServiceManager();
    const { registryAdd } = await import("../src/service/registry.js");
    await registryAdd({
      name: "my-relay",
      status: "stopped",
      platform: "linux",
      scope: "user",
      unitPath: `${fakeHome}/.config/systemd/user/my-relay.service`,
      installedAt: new Date().toISOString(),
    });
    await manager.uninstall("my-relay");
    const { registryList } = await import("../src/service/registry.js");
    expect(registryList().find((e) => e.name === "my-relay")).toBeUndefined();
  });

  it("throws SERVICE_NOT_FOUND for unknown uninstall", async () => {
    const manager = new LinuxServiceManager();
    await expect(manager.uninstall("ghost")).rejects.toThrow(
      /SERVICE_NOT_FOUND/,
    );
  });

  it("rolls back the unit file when enable fails (E9)", async () => {
    mockSpawnSync.mockImplementation((_cmd: string, args: string[]) => {
      if (args.includes("enable")) {
        return { status: 1, stdout: "", stderr: "Failed to enable" };
      }
      return { status: 0, stdout: "", stderr: "" };
    });
    const manager = new LinuxServiceManager();
    await expect(manager.install(config(), { user: true })).rejects.toThrow(
      /SERVICE_SYSTEMCTL_FAILED/,
    );
    expect(
      existsSync(`${fakeHome}/.config/systemd/user/my-relay.service`),
    ).toBe(false);
  });
});
