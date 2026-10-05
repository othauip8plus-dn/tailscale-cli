import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { cacheBinPath, ensureBinary } from "./binary.js";
import { trackedUserspaceSocket } from "./daemon.js";

const execFileAsync = promisify(execFile);

export interface LocalCommandResult<T = unknown> {
  stdout: string;
  stderr: string;
  code: number;
  json?: T;
}

export interface BinaryInfo {
  path: string;
  version: string;
}

function parseJson<T>(text: string): T | undefined {
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined;
  }
}

const SECRET_ARG_RE =
  /^(--(?:auth-key|authkey|api-key|client-secret|token|credential|password)[=])(.*)$/i;

/** Masks secret material embedded in a `tailscale` argv entry. */
export function redactArgv(args: string[]): string[] {
  return args.map((arg) => {
    const match = SECRET_ARG_RE.exec(arg);
    if (match) return `${match[1]}***`;
    return arg
      .replace(/tskey-[A-Za-z0-9._-]{4,}/g, "tskey-***")
      .replace(/(bearer|basic)\s+[A-Za-z0-9._:-]{8,}/gi, "$1 ***");
  });
}

/** Masks `tskey-…` / bearer tokens anywhere in subprocess output. */
export function sanitizeCommandText(text: string): string {
  return text
    .replace(/tskey-[A-Za-z0-9._-]{4,}/g, "tskey-***")
    .replace(/(bearer|basic)\s+[A-Za-z0-9._:-]{8,}/gi, "$1 ***")
    .replace(
      /(--(?:auth-key|authkey|api-key|client-secret|token|credential|password)=)\S+/gi,
      "$1***",
    );
}

export async function findTailscale(
  explicit?: string,
  options: { download?: boolean } = {},
): Promise<string> {
  const candidates = [
    explicit,
    process.env.TS_TAILSCALE_BIN,
    cacheBinPath(),
    process.platform === "win32" ? "tailscale.exe" : "tailscale",
    process.platform === "win32"
      ? resolvePath(
          process.env.ProgramFiles ?? "C:\\Program Files",
          "Tailscale",
          "tailscale.exe",
        )
      : "/usr/bin/tailscale",
    process.platform === "win32"
      ? resolvePath(
          process.env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)",
          "Tailscale",
          "tailscale.exe",
        )
      : "/usr/local/bin/tailscale",
  ].filter((v): v is string => !!v);

  for (const candidate of candidates) {
    try {
      const { stdout } = await execFileAsync(candidate, ["version"], {
        timeout: 10_000,
        windowsHide: true,
      });
      if (
        existsSync(candidate) ||
        candidate === "tailscale" ||
        candidate === "tailscale.exe"
      )
        return candidate;
      if (stdout.trim()) return candidate;
    } catch {
      continue;
    }
  }

  if (options.download !== false) {
    try {
      const downloaded = await ensureBinary();
      return downloaded.path;
    } catch (downloadError) {
      throw new Error(
        `TAILSCALE_BINARY_NOT_FOUND: no system binary and auto-download failed (${downloadError instanceof Error ? downloadError.message : String(downloadError)}); set TS_TAILSCALE_BIN or install Tailscale`,
      );
    }
  }

  throw new Error(
    "TAILSCALE_BINARY_NOT_FOUND: install Tailscale or set TS_TAILSCALE_BIN",
  );
}

export async function tailscaleVersion(
  bin?: string,
  options: { download?: boolean } = {},
): Promise<BinaryInfo> {
  const path = await findTailscale(bin, options);
  const { stdout, stderr } = await execFileAsync(path, ["version"], {
    timeout: 10_000,
    windowsHide: true,
  });
  const version =
    (stdout || stderr)
      .split(/\r?\n/)
      .find((line) => /\d+\.\d+\.\d+/.test(line))
      ?.trim() ?? "unknown";
  return { path, version };
}

export class TailscaleLocal {
  readonly bin: string;

  constructor(bin: string) {
    this.bin = bin;
  }

  async run(
    args: string[],
    options: { timeoutMs?: number; env?: NodeJS.ProcessEnv } = {},
  ): Promise<LocalCommandResult> {
    const socket =
      options.env?.TS_TAILSCALE_SOCKET?.trim() ??
      process.env.TS_TAILSCALE_SOCKET?.trim() ??
      (await trackedUserspaceSocket());
    const commandArgs = socket ? [`--socket=${socket}`, ...args] : args;
    try {
      const { stdout, stderr } = await execFileAsync(this.bin, commandArgs, {
        timeout: options.timeoutMs ?? 60_000,
        windowsHide: true,
        // `options.env` is authoritative when supplied: callers pass an
        // explicitly redacted environment, so merging it over process.env
        // would resurrect every credential they removed.
        env: options.env ?? process.env,
        maxBuffer: 8 * 1024 * 1024,
      });
      return { stdout, stderr, code: 0 };
    } catch (err) {
      // execFileAsync only includes stdout in the error message; tailscale
      // writes diagnostics to stderr, so re-throw with both streams.
      if (err instanceof Error && "stderr" in err) {
        const e = err as Error & { stdout?: string; stderr?: string };
        const detail = [e.stdout, e.stderr].filter(Boolean).join("\n").trim();
        // Never fall back to err.message: Node builds it as
        // `Command failed: <file> <argv>`, which embeds `--auth-key=…`.
        throw new Error(
          sanitizeCommandText(detail) ||
            `TAILSCALE_COMMAND_FAILED: ${this.bin} ${redactArgv(commandArgs).join(" ")} exited non-zero`,
        );
      }
      throw new Error(sanitizeCommandText(String(err)));
    }
  }

  async runJson<T>(
    args: string[],
    options: { timeoutMs?: number; env?: NodeJS.ProcessEnv } = {},
  ): Promise<T> {
    const result = await this.run([...args, "--json"], options);
    const parsed = parseJson<T>(result.stdout);
    if (parsed === undefined)
      throw new Error(`TAILSCALE_INVALID_JSON: ${result.stdout.slice(0, 400)}`);
    return parsed;
  }

  async status<T = Record<string, unknown>>(): Promise<T> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await this.runJson<T>(["status"]);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (!/failed to connect to local tailscaled/i.test(message))
          throw error;
        lastError = error;
        await new Promise((resolve) =>
          setTimeout(resolve, 1500 * (attempt + 1)),
        );
      }
    }
    throw lastError;
  }

  async up(args: string[], env: NodeJS.ProcessEnv): Promise<void> {
    await this.run(["up", ...args], { env, timeoutMs: 120_000 });
  }

  async update(yes = false): Promise<void> {
    await this.run(yes ? ["update", "--yes"] : ["update"], {
      timeoutMs: 180_000,
    });
  }

  async set(args: string[]): Promise<void> {
    await this.run(["set", ...args], { timeoutMs: 30_000 });
  }

  async serve(args: string[]): Promise<void> {
    await this.run(["serve", ...args], { timeoutMs: 60_000 });
  }

  async funnel(args: string[]): Promise<void> {
    await this.run(["funnel", ...args], { timeoutMs: 60_000 });
  }
}
