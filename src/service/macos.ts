import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join as joinPath } from "node:path";
import os from "node:os";
import {
  resolveUserName,
  maskEnv,
  isSecretKey,
  isSecretValue,
} from "./config.js";
import { loadRelayConfigFile } from "../relay.js";
import { registryAdd, registryRemove, registryList } from "./registry.js";
import type {
  InstallOptions,
  LogOptions,
  ServiceConfig,
  ServiceInfo,
  ServiceInstallResult,
  ServiceManager,
  ServiceStatus,
} from "./types.js";
import { cliEntrypoint, nodeExecutable } from "./linux.js";

export function agentDirUser(): string {
  return joinPath(os.homedir(), "Library", "LaunchAgents");
}

export function plistPathFor(name: string): string {
  return joinPath(agentDirUser(), `${name}.plist`);
}

export function logDirFor(name: string): string {
  return joinPath(
    process.env.HOME ?? os.homedir(),
    ".tailsacle-cli",
    "logs",
    name,
  );
}

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function renderPlist(
  config: ServiceConfig,
  opts: {
    nodePath: string;
    cliPath: string;
    outLog: string;
    errLog: string;
  },
): string {
  const execArgs = config.script
    ? [config.script, ...config.args]
    : [opts.cliPath, ...config.args];
  const programArgs = [opts.nodePath, ...execArgs]
    .map((a) => `    <string>${xmlEscape(a)}</string>`)
    .join("\n");
  const envEntries = Object.entries(config.env)
    .map(
      ([k, v]) =>
        `    <key>${xmlEscape(k)}</key>\n    <string>${xmlEscape(v)}</string>`,
    )
    .join("\n");
  const restart = config.restart.onFailure ? "<true/>" : "<false/>";
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${xmlEscape(config.name)}</string>
  <key>ProgramArguments</key>
  <array>
${programArgs}
  </array>
  <key>WorkingDirectory</key>
  <string>${xmlEscape(config.workingDir)}</string>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    ${restart}
  </dict>
  <key>ThrottleInterval</key>
  <integer>${config.restart.delaySeconds}</integer>
  <key>StandardOutPath</key>
  <string>${xmlEscape(opts.outLog)}</string>
  <key>StandardErrorPath</key>
  <string>${xmlEscape(opts.errLog)}</string>
  <key>RunAtLoad</key>
  <true/>
${
  envEntries
    ? `  <key>EnvironmentVariables</key>\n  <dict>\n${envEntries}\n  </dict>\n`
    : ""
}</dict>
</plist>
`;
}

function launchctl(
  args: string[],
  tolerateFailure = false,
): { ok: boolean; out: string } {
  const result = spawnSync("launchctl", args, { encoding: "utf8" });
  if (result.status !== 0 && !tolerateFailure) {
    const stderr = (result.stderr ?? result.stdout ?? "").trim();
    throw new Error(
      `SERVICE_LAUNCHCTL_FAILED: launchctl ${args.join(" ")} failed${
        stderr ? `: ${stderr}` : ""
      }`,
    );
  }
  return { ok: result.status === 0, out: (result.stdout ?? "").trim() };
}

export class MacOSServiceManager implements ServiceManager {
  async install(
    config: ServiceConfig,
    _opts: InstallOptions = {},
  ): Promise<ServiceInstallResult> {
    const plistPath = plistPathFor(config.name);
    if (existsSync(plistPath)) {
      throw new Error(
        `SERVICE_ALREADY_EXISTS: plist already exists at ${plistPath}`,
      );
    }
    const logDir = config.log?.dir ?? logDirFor(config.name);
    mkdirSync(logDir, { recursive: true });
    const outLog = joinPath(logDir, "out.log");
    const errLog = joinPath(logDir, "err.log");
    const plist = renderPlist(config, {
      nodePath: nodeExecutable(),
      cliPath: cliEntrypoint(),
      outLog,
      errLog,
    });
    mkdirSync(dirname(plistPath), { recursive: true });
    writeFileSync(plistPath, plist, "utf8");
    try {
      launchctl(["load", "-w", plistPath]);
    } catch (error) {
      rmSync(plistPath, { force: true });
      throw error;
    }
    // Give launchd a moment to start the job
    await new Promise((r) => setTimeout(r, 1000));
    const status = await this.status(config.name);
    const info: ServiceInfo = {
      name: config.name,
      status: status.status,
      pid: status.pid,
      platform: "darwin",
      scope: "user",
      unitPath: plistPath,
      logDir,
      installedAt: new Date().toISOString(),
    };
    await registryAdd(info);
    return {
      installed: true,
      name: config.name,
      platform: "darwin",
      scope: "user",
      unitPath: plistPath,
      status: status.status,
      pid: status.pid,
    };
  }

  async uninstall(name: string): Promise<void> {
    const info = registryList().find((e) => e.name === name);
    if (!info) {
      throw new Error(`SERVICE_NOT_FOUND: service "${name}" is not registered`);
    }
    const plistPath = info.unitPath ?? plistPathFor(name);
    if (existsSync(plistPath)) {
      launchctl(["unload", "-w", plistPath], true);
      rmSync(plistPath, { force: true });
    }
    await registryRemove(name);
  }

  async start(name: string): Promise<void> {
    launchctl(["start", name]);
  }

  async stop(name: string): Promise<void> {
    launchctl(["stop", name], true);
  }

  async restart(name: string): Promise<void> {
    await this.stop(name);
    await this.start(name);
  }

  async status(name: string): Promise<ServiceStatus> {
    const { ok, out } = launchctl(["list", name], true);
    if (!ok || !out) {
      // Not loaded
      return { name, status: "stopped" };
    }
    // launchctl list <name> outputs: PID  LastExitStatus  Label
    const pidMatch = /^\s*(\d+|-)\s/.exec(out);
    const pid =
      pidMatch && pidMatch[1] !== "-" ? Number(pidMatch[1]) : undefined;
    const status: ServiceStatus["status"] =
      pid !== undefined && pid > 0 ? "running" : "stopped";
    return { name, status, pid: pid && pid > 0 ? pid : undefined };
  }

  async logs(name: string, opts: LogOptions): Promise<void> {
    const info = registryList().find((e) => e.name === name);
    const logDir = info?.logDir ?? logDirFor(name);
    const outFile = joinPath(logDir, "out.log");
    const errFile = joinPath(logDir, "err.log");

    const tail = (filePath: string, label: string): void => {
      if (!existsSync(filePath)) {
        console.log(
          `[tailsacle-service] ${label}: no log file yet: ${filePath}`,
        );
        return;
      }
      const content = readFileSync(filePath, "utf8");
      const lines = content.split("\n").slice(-Math.max(1, opts.lines));
      console.log(lines.join("\n"));
    };

    if (opts.follow) {
      // Use tail -f -n <lines> for both files simultaneously
      const args = ["-f", "-n", String(opts.lines), outFile, errFile];
      await new Promise<void>((resolve, reject) => {
        const child = spawn("tail", args, { stdio: "inherit" });
        child.on("close", () => resolve());
        child.on("error", (error) =>
          reject(new Error(`SERVICE_TAIL_FAILED: ${error.message}`)),
        );
      });
    } else {
      tail(outFile, "stdout");
      tail(errFile, "stderr");
    }
  }

  async list(): Promise<ServiceInfo[]> {
    return registryList().map((info) => ({
      ...info,
      platform: "darwin",
    }));
  }
}

export function maskedEnvMacOS(config: ServiceConfig): Record<string, string> {
  return maskEnv(config.env);
}

export function hasSecretEnvMacOS(config: ServiceConfig): boolean {
  return Object.entries(config.env).some(
    ([key, value]) => isSecretKey(key) || isSecretValue(value),
  );
}

export function detectRelayPortsMacOS(args: string[]): number[] {
  const ports: number[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    if ((arg === "--listen" || arg === "-l") && args[i + 1]) {
      const port = Number(args[i + 1]);
      if (Number.isFinite(port) && port > 0 && port <= 65535) ports.push(port);
    }
    if ((arg === "--file" || arg === "-f") && args[i + 1]) {
      try {
        for (const m of loadRelayConfigFile(args[i + 1]!)) {
          if (m.listenPort > 0 && m.listenPort <= 65535)
            ports.push(m.listenPort);
        }
      } catch {
        // ignore unreadable relay config file
      }
    }
  }
  return [...new Set(ports)];
}

export function resolveUserMacOS(user: string): string {
  return resolveUserName(user);
}
