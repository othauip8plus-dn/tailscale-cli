import { readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import os from "node:os";
import type { CredentialResolution, Profile, ResolvedConfig } from "./types.js";

const namedCredentialEnv = [
  "TS_TRUST_CREDENTIAL",
  "TS_API_TRUST",
  "TAILSCALE_TRUST_CREDENTIAL",
  "TAILSCALE_API_TRUST",
] as const;

export function maskSecret(value: string): string {
  return value.length < 10 ? "***" : `${value.slice(0, 5)}…${value.slice(-3)}`;
}

export function credentialEnvName(
  env: NodeJS.ProcessEnv = process.env,
  preferredName?: string,
): string | undefined {
  if (preferredName) {
    const value = env[preferredName]?.trim();
    return value?.startsWith("tskey-client-") ? preferredName : undefined;
  }
  const resolved = resolveCredential(env);
  return resolved.found ? resolved.source : undefined;
}

export function resolveCredential(
  env: NodeJS.ProcessEnv = process.env,
): CredentialResolution {
  const exactTrustMatches = Object.entries(env).filter(([, value]) =>
    value?.startsWith("tskey-client-"),
  );
  const selectedName = env.TS_CREDENTIAL_ENV?.trim();
  const explicit = env.TS_CLIENT_SECRET?.trim();
  const named = namedCredentialEnv.find((name) => Boolean(env[name]?.trim()));
  const selected = selectedName
    ? env[selectedName]?.trim()
      ? ([selectedName, env[selectedName]!.trim()] as const)
      : undefined
    : explicit
      ? (["TS_CLIENT_SECRET", explicit] as const)
      : named
        ? ([named, env[named]!.trim()] as const)
        : exactTrustMatches.length === 1
          ? ([exactTrustMatches[0]![0], exactTrustMatches[0]![1]!] as const)
          : undefined;

  const candidates = exactTrustMatches.map(([name]) => name);
  if (selectedName) {
    if (!env[selectedName]?.trim())
      return {
        found: false,
        candidates: [selectedName],
        error: "CREDENTIAL_ENV_MISSING",
      };
    if (!env[selectedName]!.trim().startsWith("tskey-client-"))
      return {
        found: false,
        candidates: [selectedName],
        error: "CREDENTIAL_FORMAT_UNSUPPORTED",
      };
  }
  if (exactTrustMatches.length > 1 && !selectedName && !explicit && !named) {
    return { found: false, candidates, error: "MULTIPLE_CREDENTIALS" };
  }
  if (!selected) {
    return { found: false, candidates, error: "CREDENTIAL_NOT_FOUND" };
  }
  return {
    found: true,
    source: selected[0],
    masked: maskSecret(selected[1]),
    candidates: explicit
      ? candidates.filter((name) => name !== "TS_CLIENT_SECRET")
      : candidates,
  };
}

function bool(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined) return defaultValue;
  return ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
}

function number(value: string | undefined, defaultValue: number): number {
  if (value === undefined) return defaultValue;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : defaultValue;
}

function slug(value: string): string {
  return (
    value
      .toLowerCase()
      .replace(/[^a-z0-9-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 63) || "tailscale-node"
  );
}

interface ConfigFile {
  profile?: string;
  tailnet?: string;
  hostname?: string;
  tags?: string[];
  ssh?: boolean;
  keyExpiry?: string;
  preauthorized?: boolean;
  reusable?: boolean;
  ephemeral?: boolean;
  acceptDns?: boolean;
  acceptRoutes?: boolean;
  cleanupAfter?: number;
  credentialEnv?: string;
  tagOwner?: string[];
}

export function loadConfigFile(
  configPath?: string,
): { config: ConfigFile; source: string } | undefined {
  const candidates = configPath
    ? [configPath]
    : [
        resolvePath(process.cwd(), "tailscale-cli.config.json"),
        resolvePath(process.cwd(), "tailscale-cli.config.jsonc"),
      ];
  for (const candidate of candidates) {
    try {
      const raw = readFileSync(candidate, "utf8");
      const cleaned = raw
        .replace(/"(?:[^"\\]|\\.)*"|\/\/[^\n]*/g, (match) =>
          match.startsWith('"') ? match : "",
        )
        .replace(/,\s*([\]}])/g, "$1");
      const parsed = JSON.parse(cleaned) as ConfigFile;
      return { config: parsed, source: candidate };
    } catch {
      // File not found or invalid; try next.
    }
  }
  return undefined;
}

function profileFromEnvironment(env: NodeJS.ProcessEnv): Profile {
  const configured = env.TS_PROFILE as Profile | undefined;
  if (configured) return configured;
  if (env.CI || env.GITHUB_ACTIONS) return "ci";
  if (env.KUBERNETES_SERVICE_HOST || env.CONTAINER) return "container";
  if (process.platform === "win32") return "windows";
  return "dev";
}

export function resolveConfig(
  env: NodeJS.ProcessEnv = process.env,
): ResolvedConfig {
  const profile = profileFromEnvironment(env);
  const ephemeral = bool(
    env.TS_EPHEMERAL,
    profile === "ci" || profile === "container",
  );
  const tags = (env.TS_TAGS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const warnings: string[] = [];
  if (!tags.length && ["container", "ci", "vm", "funnel-app"].includes(profile))
    warnings.push(
      "NO_TAGS_CONFIGURED: reusable infrastructure should normally use a tag",
    );
  if (env.TS_TAILNET === undefined)
    warnings.push('TAILNET_DEFAULTED: using tailnet "-"');
  if (
    env.TS_TAILNET !== undefined &&
    !/^[a-zA-Z0-9][a-zA-Z0-9-]*\.ts\.net$/.test(env.TS_TAILNET)
  )
    warnings.push(
      `TAILNET_DOMAIN_UNUSUAL: "${env.TS_TAILNET}" is not a default *.ts.net tailnet; Funnel DNS and HTTPS rely on a Tailscale-hosted domain`,
    );

  let hostname = slug(env.TS_HOSTNAME || os.hostname());
  if (!env.TS_HOSTNAME && profile === "ci") {
    const runId =
      env.GITHUB_RUN_ID || env.CI_BUILD_ID || env.CIRCLE_WORKFLOW_ID || "";
    if (runId) hostname = `${slug(os.hostname())}-${runId}`.slice(0, 63);
  }

  const reusable = bool(
    env.TS_REUSABLE,
    !ephemeral &&
      (profile === "vm" || profile === "windows" || profile === "funnel-app"),
  );
  if (env.TS_REUSABLE === undefined && reusable)
    warnings.push(
      "REUSABLE_KEY_DEFAULTED: auth key created for this long-lived node is reusable until it expires",
    );

  const stateDir = env.TS_STATE_DIR?.trim() || undefined;
  return {
    profile,
    tailnet: env.TS_TAILNET?.trim() || "-",
    hostname,
    tags,
    ssh: bool(env.TS_SSH, true),
    keyExpiry: env.TS_KEY_EXPIRY?.trim() || "max",
    preauthorized: bool(env.TS_PREAUTHORIZED, true),
    reusable,
    ephemeral,
    acceptDns: bool(env.TS_ACCEPT_DNS, true),
    acceptRoutes: bool(
      env.TS_ACCEPT_ROUTES,
      profile === "subnet-router" || profile === "exit-node",
    ),
    cleanupAfter: number(env.TS_CLEANUP_OFFLINE_AFTER, 3600),
    ...(stateDir ? { stateDir } : {}),
    source: {
      profile: env.TS_PROFILE ? "TS_PROFILE" : "runtime",
      hostname: env.TS_HOSTNAME
        ? "TS_HOSTNAME"
        : profile === "ci"
          ? "os.hostname+run"
          : "os.hostname",
      tags: env.TS_TAGS ? "TS_TAGS" : "default",
      keyExpiry: env.TS_KEY_EXPIRY ? "TS_KEY_EXPIRY" : "default",
    },
    warnings,
  };
}

export const runtime = Object.freeze({
  node: process.version,
  platform: process.platform,
  arch: process.arch,
  cwd: process.cwd(),
});

export type ResolvedAuth =
  | { kind: "node-auth-key"; source: string; masked: string }
  | { kind: "oauth-trust"; source: string; masked: string }
  | { kind: "oauth-pair"; source: string; clientId: string }
  | { kind: "bearer"; source: string; masked: string }
  | { kind: "api-key"; source: string; masked: string };

export interface AuthResolution {
  found: boolean;
  auth?: ResolvedAuth;
  candidates: string[];
  error?: string;
}

export function resolveAuth(
  env: NodeJS.ProcessEnv = process.env,
): AuthResolution {
  const authKey = env.TS_AUTH_KEY?.trim();
  if (authKey)
    return {
      found: true,
      auth: {
        kind: "node-auth-key",
        source: "TS_AUTH_KEY",
        masked: maskSecret(authKey),
      },
      candidates: [],
    };

  const trust = resolveCredential(env);
  if (trust.error === "MULTIPLE_CREDENTIALS")
    return {
      found: false,
      candidates: trust.candidates,
      error: "MULTIPLE_CREDENTIALS",
    };
  if (trust.found && trust.source) {
    const value = env[trust.source]?.trim() ?? "";
    return {
      found: true,
      auth: {
        kind: "oauth-trust",
        source: trust.source,
        masked: maskSecret(value),
        ...(env.TS_CLIENT_ID ? { clientId: env.TS_CLIENT_ID } : {}),
      },
      candidates: trust.candidates,
    };
  }

  const clientId = env.TS_OAUTH_CLIENT_ID ?? env.TS_CLIENT_ID;
  const clientSecret = env.TS_OAUTH_CLIENT_SECRET ?? env.TS_CLIENT_SECRET;
  if (clientId?.trim() && clientSecret?.trim())
    return {
      found: true,
      auth: {
        kind: "oauth-pair",
        source:
          clientId === env.TS_CLIENT_ID
            ? "TS_CLIENT_ID+TS_CLIENT_SECRET"
            : "TS_OAUTH_CLIENT_ID+TS_OAUTH_CLIENT_SECRET",
        clientId: clientId.trim(),
      },
      candidates: [],
    };

  const accessToken = env.TS_ACCESS_TOKEN ?? env.TS_API_TOKEN;
  if (accessToken?.trim())
    return {
      found: true,
      auth: {
        kind: "bearer",
        source: env.TS_ACCESS_TOKEN ? "TS_ACCESS_TOKEN" : "TS_API_TOKEN",
        masked: maskSecret(accessToken.trim()),
      },
      candidates: [],
    };

  if (env.TS_API_KEY?.trim())
    return {
      found: true,
      auth: {
        kind: "api-key",
        source: "TS_API_KEY",
        masked: maskSecret(env.TS_API_KEY.trim()),
      },
      candidates: [],
    };

  return {
    found: false,
    candidates: trust.candidates,
    error: "CREDENTIAL_NOT_FOUND",
  };
}
