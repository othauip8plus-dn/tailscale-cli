import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  watchFile,
  writeFileSync,
} from "node:fs";
import { join as joinPath } from "node:path";
import { createRequire } from "node:module";
import { cliEntrypoint, nodeExecutable } from "./linux.js";
import { registryAdd, registryRemove, registryList } from "./registry.js";
import { maskEnv } from "./config.js";
import type {
  InstallOptions,
  LogOptions,
  ServiceConfig,
  ServiceInfo,
  ServiceInstallResult,
  ServiceManager,
  ServiceStatus,
} from "./types.js";

const require = createRequire(import.meta.url);

function loadWinSwBinary(): { exe: string; config: string } {
  if (process.platform !== "win32") {
    throw new Error(
      "SERVICE_PLATFORM_UNSUPPORTED: Windows service manager requires win32",
    );
  }
  try {
    const pkgRoot = dirname(require.resolve("node-windows/package.json"));
    const exe = joinPath(pkgRoot, "bin", "winsw", "winsw.exe");
    const cfg = joinPath(pkgRoot, "bin", "winsw", "winsw.exe.config");
    if (!existsSync(exe)) {
      throw new Error(`winsw.exe not found at ${exe}`);
    }
    return { exe, config: cfg };
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(
      `SERVICE_WINDOWS_NATIVE_REQUIRED: node-windows is unavailable (${detail}); install tailsacle-cli with its dependencies or use "service install --scheduler" (Task Scheduler, no admin needed)`,
    );
  }
}

function dirname(p: string): string {
  return p.split(/[\\/]/).slice(0, -1).join("/");
}

function windowsServiceDir(name: string): string {
  return joinPath(
    process.env.ProgramData ?? "C:\\ProgramData",
    "tailsacle-cli",
    "services",
    name,
  );
}

function isElevatedPowerShell(): boolean {
  const result = spawnSync(
    "powershell",
    [
      "-NoProfile",
      "-Command",
      "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
    ],
    { encoding: "utf8" },
  );
  return result.status === 0 && result.stdout?.trim() === "True";
}

export function isAdminUser(): boolean {
  if (process.platform !== "win32") return false;
  try {
    return isElevatedPowerShell();
  } catch {
    return false;
  }
}

function quoteForPwsh(value: string): string {
  return value.replace(/'/g, "''");
}

export function elevateCommand(): string[] {
  const argList = process.argv
    .slice(1)
    .map((a) => `'${quoteForPwsh(a)}'`)
    .join(",");
  return [
    "-NoProfile",
    "-Command",
    `Start-Process -FilePath '${process.execPath}' -ArgumentList ${argList} -Verb RunAs`,
  ];
}

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function renderWinSwXml(
  config: ServiceConfig,
  opts: { nodePath: string; cliPath: string },
): string {
  const execArgs = config.script
    ? [config.script, ...config.args]
    : [opts.cliPath, ...config.args];
  const argLines = execArgs
    .map((a) => `  <argument>${xmlEscape(a)}</argument>`)
    .join("\n");
  const envLines = Object.entries(config.env)
    .map(
      ([key, value]) =>
        `  <env name="${xmlEscape(key)}" value="${xmlEscape(value)}" />`,
    )
    .join("\n");
  return `<service>
  <id>${xmlEscape(config.name)}</id>
  <name>${xmlEscape(config.name)}</name>
  <description>${xmlEscape(config.description ?? "")}</description>
  <executable>${xmlEscape(opts.nodePath)}</executable>
${argLines}
  <workingdirectory>${xmlEscape(config.workingDir)}</workingdirectory>
  <logpath>${xmlEscape(config.log?.dir ?? joinPath(windowsServiceDir(config.name), "logs"))}</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>${(config.log?.maxSizeMb ?? 10) * 1024}</sizeThreshold>
    <keepFiles>${config.log?.keepFiles ?? 5}</keepFiles>
  </log>
  <onfailure action="restart" delay="${config.restart.delaySeconds} sec" />
  <resetfailure>1 hour</resetfailure>
${envLines ? `${envLines}\n` : ""}</service>
`;
}

function scQuery(name: string): string {
  const result = spawnSync("sc", ["query", name], { encoding: "utf8" });
  return result.status === 0 ? (result.stdout ?? "") : "";
}

function runWinSw(
  exePath: string,
  args: string[],
  errorCode: string,
  tolerateFailure = false,
): void {
  const result = spawnSync(exePath, args, { encoding: "utf8" });
  if (result.status !== 0 && !tolerateFailure) {
    const stderr = (result.stderr ?? result.stdout ?? "").trim();
    throw new Error(
      `${errorCode}: ${exePath} ${args.join(" ")} failed${
        stderr ? `: ${stderr}` : ""
      }`,
    );
  }
}

async function removeDirRetry(dir: string, attempts = 5): Promise<void> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
      return;
    } catch {
      if (attempt === attempts - 1) return;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
}

async function scStopAndDelete(name: string): Promise<void> {
  spawnSync("sc", ["stop", name], { encoding: "utf8" });
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const output = scQuery(name);
    if (!output || /STOPPED/.test(output)) break;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  spawnSync("sc", ["delete", name], { encoding: "utf8" });
}

export function parseScStatus(name: string, output: string): ServiceStatus {
  if (!output) return { name, status: "unknown" };
  const stateMatch = /STATE\s*:\s*\d+\s+(\w+)/.exec(output);
  const pidMatch = /PID\s*:\s*(\d+)/.exec(output);
  const state = stateMatch?.[1] ?? "";
  let status: ServiceStatus["status"];
  if (state === "RUNNING") status = "running";
  else if (state === "STOPPED") status = "stopped";
  else status = "unknown";
  const pid = pidMatch ? Number(pidMatch[1]) : undefined;
  return {
    name,
    status,
    pid: pid && pid > 0 ? pid : undefined,
  };
}

export class WindowsServiceManager implements ServiceManager {
  async install(
    config: ServiceConfig,
    _opts: InstallOptions = {},
  ): Promise<ServiceInstallResult> {
    const serviceDir = windowsServiceDir(config.name);
    mkdirSync(serviceDir, { recursive: true });
    // B10 fix: tighten ACL on the service directory so that the WinSW XML
    // (which contains env vars including PGPASSWORD) is not readable by
    // unprivileged users.  ProgramData defaults give "Users" read access;
    // we remove inherited permissions and grant only SYSTEM + Administrators.
    try {
      spawnSync(
        "icacls",
        [
          serviceDir,
          "/inheritance:r",
          "/grant:r",
          "SYSTEM:(OI)(CI)F",
          "/grant:r",
          "Administrators:(OI)(CI)F",
        ],
        { encoding: "utf8" },
      );
    } catch {
      // Non-fatal: icacls may be unavailable in some environments; log a
      // warning but do not abort the install.
      console.warn(
        `[tailsacle-service] WARNING: could not tighten ACL on ${serviceDir}; secrets in ${config.name}.xml may be readable by other users`,
      );
    }
    const winsw = loadWinSwBinary();
    const cliPath = cliEntrypoint();
    const nodePath = nodeExecutable();
    const logDir = config.log?.dir ?? joinPath(serviceDir, "logs");
    mkdirSync(logDir, { recursive: true });
    const exePath = joinPath(serviceDir, `${config.name}.exe`);
    const xmlPath = joinPath(serviceDir, `${config.name}.xml`);
    copyFileSync(winsw.exe, exePath);
    copyFileSync(winsw.config, `${exePath}.config`);
    writeFileSync(
      xmlPath,
      renderWinSwXml(config, { nodePath, cliPath }),
      "utf8",
    );
    runWinSw(exePath, ["install"], `SERVICE_WINDOWS_INSTALL_FAILED`);
    runWinSw(exePath, ["start"], `SERVICE_WINDOWS_START_FAILED`, true);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const status = await this.status(config.name);
    const info: ServiceInfo = {
      name: config.name,
      status: status.status,
      pid: status.pid,
      platform: "win32",
      scope: "system",
      unitPath: serviceDir,
      logDir,
      installedAt: new Date().toISOString(),
    };
    await registryAdd(info);
    return {
      installed: true,
      name: config.name,
      platform: "win32",
      scope: "system",
      unitPath: serviceDir,
      status: status.status,
      pid: status.pid,
    };
  }

  async uninstall(name: string): Promise<void> {
    const info = registryList().find((e) => e.name === name);
    if (!info) {
      throw new Error(`SERVICE_NOT_FOUND: service "${name}" is not registered`);
    }
    const serviceDir = info.unitPath ?? windowsServiceDir(name);
    await scStopAndDelete(name);
    await removeDirRetry(serviceDir);
    await registryRemove(name);
  }

  async start(name: string): Promise<void> {
    const result = spawnSync("sc", ["start", name], { encoding: "utf8" });
    if (result.status !== 0) {
      const stderr = (result.stderr ?? "").trim();
      throw new Error(
        `SERVICE_WINDOWS_START_FAILED: sc start ${name} failed${
          stderr ? `: ${stderr}` : ""
        }`,
      );
    }
  }

  async stop(name: string): Promise<void> {
    spawnSync("sc", ["stop", name], { encoding: "utf8" });
  }

  async restart(name: string): Promise<void> {
    await this.stop(name);
    await this.start(name);
  }

  async status(name: string): Promise<ServiceStatus> {
    const output = scQuery(name);
    if (!output) {
      throw new Error(`SERVICE_NOT_FOUND: service "${name}" is not installed`);
    }
    return parseScStatus(name, output);
  }

  async logs(name: string, opts: LogOptions): Promise<void> {
    const info = registryList().find((e) => e.name === name);
    const logDir =
      info?.logDir ??
      (info?.unitPath
        ? joinPath(info.unitPath, "logs")
        : joinPath(windowsServiceDir(name), "logs"));
    const outFile = joinPath(logDir, `${name}.out.log`);
    const errFile = joinPath(logDir, `${name}.err.log`);
    const tail = (filePath: string): void => {
      if (!existsSync(filePath)) {
        console.log(`[tailsacle-service] no log file yet: ${filePath}`);
        return;
      }
      const fd = readFileSync(filePath, "utf8");
      const lines = fd.split("\n").slice(-opts.lines);
      console.log(lines.join("\n"));
    };
    tail(outFile);
    tail(errFile);
    if (opts.follow) {
      await new Promise<void>((resolve) => {
        const watch = (filePath: string): void => {
          if (!existsSync(filePath)) return;
          watchFile(filePath, { interval: 1000 }, () => {
            tail(filePath);
          });
        };
        watch(outFile);
        watch(errFile);
        process.once("SIGINT", () => resolve());
        process.once("SIGTERM", () => resolve());
      });
    }
  }

  async list(): Promise<ServiceInfo[]> {
    return registryList().map((info) => ({
      ...info,
      platform: "win32",
    }));
  }
}

export function maskedEnvWindows(
  config: ServiceConfig,
): Record<string, string> {
  return maskEnv(config.env);
}
