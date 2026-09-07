import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { TailscaleApiClient } from "./api.js";
import { ensureHuJsonArrayItem, ensureHuJsonKey } from "./hujson.js";
import type { PolicyDocument, ResolvedConfig } from "./types.js";
import { confirm } from "./interactive.js";

export interface PolicySyncResult {
  changed: boolean;
  validated: boolean;
  written: boolean;
  etag?: string;
  backup?: string;
  diff: string;
}

export interface ProvisionResult {
  provisioned: boolean;
  warnings: string[];
  backup?: string;
}

function normalizeTag(tag: string): string {
  return tag.startsWith("tag:") ? tag : `tag:${tag}`;
}

function tagOwnersOf(
  policy: PolicyDocument | undefined,
): Record<string, string[]> {
  const value = policy?.tagOwners;
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, string[]>;
}

function uniqueOwners(policy: PolicyDocument | undefined): string[] {
  const sets = new Set(
    Object.values(tagOwnersOf(policy)).map((owners) => JSON.stringify(owners)),
  );
  if (sets.size !== 1) return [];
  const parsed = JSON.parse([...sets][0]!) as unknown;
  return Array.isArray(parsed) ? (parsed as string[]) : [];
}

export interface NodeAttrEntry {
  target: string[];
  attr: string[];
}

export function nodeAttrsOf(
  policy: PolicyDocument | undefined,
): NodeAttrEntry[] {
  const value = policy?.nodeAttrs;
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is NodeAttrEntry => {
    if (!entry || typeof entry !== "object") return false;
    const target = (entry as { target?: unknown }).target;
    const attr = (entry as { attr?: unknown }).attr;
    return Array.isArray(target) && Array.isArray(attr);
  });
}

export function funnelCovered(
  policy: PolicyDocument | undefined,
  tags: string[],
): boolean {
  const targets = normalizeTagsFor(tags);
  const existing = nodeAttrsOf(policy)
    .filter((entry) => entry.attr.includes("funnel"))
    .flatMap((entry) => entry.target);
  return targets.every((target) => existing.includes(target));
}

export interface SshRuleEntry {
  action: "accept" | "check";
  src: string[];
  dst: string[];
  users: string[];
}

export function sshRulesOf(policy: PolicyDocument | undefined): SshRuleEntry[] {
  const value = policy?.ssh;
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is SshRuleEntry => {
    if (!entry || typeof entry !== "object") return false;
    const action = (entry as { action?: unknown }).action;
    const src = (entry as { src?: unknown }).src;
    const dst = (entry as { dst?: unknown }).dst;
    const users = (entry as { users?: unknown }).users;
    return (
      (action === "accept" || action === "check") &&
      Array.isArray(src) &&
      Array.isArray(dst) &&
      Array.isArray(users)
    );
  });
}

export function sshCovered(
  policy: PolicyDocument | undefined,
  tags: string[],
): boolean {
  const targets = normalizeTagsFor(tags);
  const rules = sshRulesOf(policy);
  return targets.every((target) =>
    rules.some(
      (rule) =>
        (rule.action === "accept" || rule.action === "check") &&
        (rule.dst.includes(target) ||
          rule.dst.includes("autogroup:self") ||
          rule.dst.includes("autogroup:member") ||
          rule.dst.includes("*")),
    ),
  );
}

function normalizeTagsFor(tags: string[]): string[] {
  const normalized = tags.map(normalizeTag).filter(Boolean);
  return normalized.length ? normalized : ["autogroup:member"];
}

function simpleDiff(before: string, after: string): string {
  if (before === after) return "";
  const a = before.split(/\r?\n/);
  const b = after.split(/\r?\n/);
  const lines: string[] = [];
  const size = Math.max(a.length, b.length);
  for (let i = 0; i < size; i += 1) {
    if (a[i] === b[i]) continue;
    if (a[i] !== undefined) lines.push(`-${a[i]}`);
    if (b[i] !== undefined) lines.push(`+${b[i]}`);
  }
  return lines.join("\n");
}

export async function policySync(
  config: ResolvedConfig,
  file: string,
  options: {
    dryRun: boolean;
    yes: boolean;
    credentialEnvName?: string;
    backupDir?: string;
  },
): Promise<PolicySyncResult> {
  if (!existsSync(file)) throw new Error(`POLICY_FILE_NOT_FOUND: ${file}`);
  const desired = await readFile(file, "utf8");
  if (!desired.trim()) throw new Error("POLICY_FILE_EMPTY");

  const api = new TailscaleApiClient(
    config,
    process.env,
    options.credentialEnvName,
  );
  const current = await api.getPolicy();
  const diff = simpleDiff(current.content, desired);
  if (!diff)
    return {
      changed: false,
      validated: true,
      written: false,
      ...(current.etag ? { etag: current.etag } : {}),
      diff: "",
    };

  await api.validatePolicyText(desired);
  if (options.dryRun)
    return {
      changed: true,
      validated: true,
      written: false,
      ...(current.etag ? { etag: current.etag } : {}),
      diff,
    };

  const approved = await confirm(
    "Apply the policy diff to the tailnet?",
    options.yes,
  );
  if (!approved)
    throw new Error(
      "POLICY_CONFIRMATION_REQUIRED: use --yes in CI or confirm in a TTY",
    );

  const backupDir = options.backupDir;
  const backup = backupDir
    ? `${backupDir}/${file.split("/").pop()}.bak`
    : `${file}.bak`;
  if (backupDir) {
    const { mkdirSync } = await import("node:fs");
    try {
      mkdirSync(backupDir, { recursive: true });
    } catch {
      // best-effort
    }
  }
  await writeFile(backup, current.content, "utf8");
  await api.updatePolicy(desired, current.etag);
  const verified = await api.getPolicy();
  if (!verified.json)
    throw new Error("POLICY_VERIFY_FAILED: API returned no policy");
  return {
    changed: true,
    validated: true,
    written: true,
    ...(verified.etag ? { etag: verified.etag } : {}),
    backup,
    diff,
  };
}

export async function ensureHttpsEnabled(
  config: ResolvedConfig,
  options: { yes: boolean; credentialEnvName?: string },
): Promise<ProvisionResult> {
  const api = new TailscaleApiClient(
    config,
    process.env,
    options.credentialEnvName,
  );
  if (!api.hasCredentials()) return { provisioned: false, warnings: [] };
  let httpsEnabled: boolean | undefined;
  try {
    httpsEnabled = (await api.getTailnetSettings()).httpsEnabled;
  } catch {
    httpsEnabled = undefined;
  }
  if (httpsEnabled === true) return { provisioned: false, warnings: [] };
  const approved = await confirm(
    "Enable HTTPS certificates for the tailnet (required for Serve/Funnel)?",
    options.yes,
  );
  if (!approved)
    throw new Error(
      "HTTPS_ENABLE_CONFIRMATION_REQUIRED: pass --yes to enable HTTPS",
    );
  await api.enableHttps();
  return {
    provisioned: true,
    warnings: ["ENABLED_HTTPS: enabled tailnet HTTPS certificates"],
  };
}

export function policyFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  return env.TS_POLICY_FILE || env.TS_POLICY;
}

async function syncPolicyHuJson(
  api: TailscaleApiClient,
  currentRaw: string,
  merged: string,
  etag: string | undefined,
  labels: string[],
  backupDir?: string,
): Promise<{ backup?: string }> {
  await api.validatePolicyText(merged);
  if (merged === currentRaw) return {};
  const backupName = `policy.provision-${Date.now()}.bak`;
  const backup = backupDir ? `${backupDir}/${backupName}` : backupName;
  if (backupDir) {
    const { mkdirSync } = await import("node:fs");
    try {
      mkdirSync(backupDir, { recursive: true });
    } catch {
      // best-effort
    }
  }
  await writeFile(backup, currentRaw, "utf8");
  await api.updatePolicy(merged, etag);
  const verified = await api.getPolicy();
  if (!verified.json)
    throw new Error(
      `POLICY_VERIFY_FAILED: HuJSON write for ${labels.join(", ")} was not reflected`,
    );
  return { backup };
}

export async function ensureDeployTags(
  config: ResolvedConfig,
  tags: string[],
  options: {
    yes: boolean;
    credentialEnvName?: string;
    owner?: string[];
    backupDir?: string;
  },
): Promise<ProvisionResult> {
  const normalized = tags.map(normalizeTag).filter(Boolean);
  if (!normalized.length) return { provisioned: false, warnings: [] };
  const api = new TailscaleApiClient(
    config,
    process.env,
    options.credentialEnvName,
  );
  const current = await api.getPolicy();
  const tagOwners = tagOwnersOf(current.json);
  const missing = normalized.filter((tag) => !(tag in tagOwners));
  if (!missing.length) return { provisioned: false, warnings: [] };

  const owner = options.owner?.length
    ? options.owner
    : uniqueOwners(current.json);
  if (!owner.length)
    throw new Error(
      "POLICY_TAG_OWNER_REQUIRED: could not determine a safe owner for the missing tagOwners (the policy has no tagOwners or mixes different owners); pass --tag-owner <owner> or set TS_TAG_OWNER",
    );
  const raw = await api.getPolicyHuJson();
  const merged = ensureHuJsonKey(
    raw.content,
    "tagOwners",
    Object.fromEntries(missing.map((tag) => [tag, owner])),
  );
  if (merged === raw.content)
    throw new Error(
      "POLICY_HUJSON_MERGE_FAILED: could not locate tagOwners in the tailnet policy",
    );
  const approved = await confirm(
    `Auto-add tagOwners ${missing.join(", ")} (owned by ${owner.join(", ")}) to the tailnet policy?`,
    options.yes,
  );
  if (!approved)
    throw new Error(
      "POLICY_PROVISION_CONFIRMATION_REQUIRED: pass --yes to auto-provision tags",
    );
  const { backup } = await syncPolicyHuJson(
    api,
    raw.content,
    merged,
    raw.etag,
    missing,
    options.backupDir,
  );
  const warnings = [
    `PROVISIONED_TAGS: added tagOwners for ${missing.join(", ")} (${owner.join(", ")}) via HuJSON-preserving write`,
  ];
  if (backup)
    warnings.push(`POLICY_BACKUP: pre-write policy saved to ${backup}`);
  return { provisioned: true, warnings, ...(backup ? { backup } : {}) };
}

export async function ensureFunnelAccess(
  config: ResolvedConfig,
  tags: string[],
  options: {
    yes: boolean;
    credentialEnvName?: string;
    backupDir?: string;
  },
): Promise<ProvisionResult> {
  const api = new TailscaleApiClient(
    config,
    process.env,
    options.credentialEnvName,
  );
  const current = await api.getPolicy();
  const targets = tags.map(normalizeTag).filter(Boolean);
  const funnelTargets = targets.length ? targets : ["autogroup:member"];
  const existing = nodeAttrsOf(current.json)
    .filter((entry) => entry.attr.includes("funnel"))
    .flatMap((entry) => entry.target);
  const needed = funnelTargets.filter((target) => !existing.includes(target));
  if (!needed.length) return { provisioned: false, warnings: [] };

  const raw = await api.getPolicyHuJson();
  let merged = raw.content;
  for (const target of needed)
    merged = ensureHuJsonArrayItem(merged, "nodeAttrs", {
      target: [target],
      attr: ["funnel"],
    });
  if (merged === raw.content)
    throw new Error(
      "POLICY_HUJSON_MERGE_FAILED: could not locate nodeAttrs in the tailnet policy",
    );
  const approved = await confirm(
    `Auto-add funnel node attribute for ${funnelTargets.join(", ")} to the tailnet policy?`,
    options.yes,
  );
  if (!approved)
    throw new Error(
      "POLICY_PROVISION_CONFIRMATION_REQUIRED: pass --yes to auto-enable funnel",
    );
  const { backup } = await syncPolicyHuJson(
    api,
    raw.content,
    merged,
    raw.etag,
    needed,
    options.backupDir,
  );
  const warnings = [
    `PROVISIONED_FUNNEL: added funnel node attribute for ${needed.join(", ")} via HuJSON-preserving write`,
  ];
  if (backup)
    warnings.push(`POLICY_BACKUP: pre-write policy saved to ${backup}`);
  return {
    provisioned: true,
    warnings,
    ...(backup ? { backup } : {}),
  };
}

export async function ensureSshAccess(
  config: ResolvedConfig,
  tags: string[],
  options: {
    yes: boolean;
    credentialEnvName?: string;
    backupDir?: string;
  },
): Promise<ProvisionResult> {
  const api = new TailscaleApiClient(
    config,
    process.env,
    options.credentialEnvName,
  );
  const current = await api.getPolicy();
  const targets = tags.map(normalizeTag).filter(Boolean);
  const sshTargets = targets.length ? targets : ["autogroup:member"];
  const rules = sshRulesOf(current.json);
  const needed = sshTargets.filter(
    (target) =>
      !rules.some(
        (rule) =>
          (rule.action === "accept" || rule.action === "check") &&
          (rule.dst.includes(target) ||
            rule.dst.includes("autogroup:self") ||
            rule.dst.includes("autogroup:member") ||
            rule.dst.includes("*")),
      ),
  );
  if (!needed.length) return { provisioned: false, warnings: [] };

  const raw = await api.getPolicyHuJson();
  let merged = raw.content;
  for (const target of needed)
    merged = ensureHuJsonArrayItem(merged, "ssh", {
      action: "accept",
      src: ["autogroup:member"],
      dst: [target],
      users: ["autogroup:nonroot", "root"],
    });
  if (merged === raw.content)
    throw new Error(
      "POLICY_HUJSON_MERGE_FAILED: could not locate ssh in the tailnet policy",
    );
  const approved = await confirm(
    `Auto-add SSH policy accept rule for ${sshTargets.join(", ")} to the tailnet policy?`,
    options.yes,
  );
  if (!approved)
    throw new Error(
      "POLICY_PROVISION_CONFIRMATION_REQUIRED: pass --yes to auto-enable SSH policy",
    );
  const { backup } = await syncPolicyHuJson(
    api,
    raw.content,
    merged,
    raw.etag,
    needed,
    options.backupDir,
  );
  const warnings = [
    `PROVISIONED_SSH: added SSH policy accept rule for ${needed.join(", ")} via HuJSON-preserving write`,
  ];
  if (backup)
    warnings.push(`POLICY_BACKUP: pre-write policy saved to ${backup}`);
  return {
    provisioned: true,
    warnings,
    ...(backup ? { backup } : {}),
  };
}
