import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { ApiError, TailscaleApiClient } from "./api.js";
import type { PolicySnapshot } from "./api.js";
import {
  ensureHuJsonArrayItem,
  ensureHuJsonKey,
  parseHuJson,
} from "./hujson.js";
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
  const targets = normalizeTagsFor(policy, tags);
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
  const targets = normalizeTagsFor(policy, tags);
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

function normalizeTagsFor(
  policy: PolicyDocument | undefined,
  tags: string[],
): string[] {
  const normalized = tags.map(normalizeTag).filter(Boolean);
  return normalized.length ? normalized : ["autogroup:member"];
}

/**
 * Renders a policy document as canonical JSON so two representations of the
 * same policy (raw HuJSON vs. the API's re-serialised JSON) compare equal.
 * Falls back to the raw text when the input is not parseable.
 */
function canonicalizePolicy(text: string): string {
  try {
    return JSON.stringify(parseHuJson(text), null, 2);
  } catch {
    return text;
  }
}

/**
 * Line diff based on a longest-common-subsequence table. A positional
 * comparison would report every following line as changed after a single
 * insertion, which makes the confirmation prompt useless.
 */
function simpleDiff(before: string, after: string): string {
  if (before === after) return "";
  const a = before.split(/\r?\n/);
  const b = after.split(/\r?\n/);
  // Guard against quadratic blowup on large policies.
  if (a.length * b.length > 4_000_000) return `~ ${before} -> ${after}`;
  const lcs: number[][] = Array.from({ length: a.length + 1 }, () =>
    new Array<number>(b.length + 1).fill(0),
  );
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      const row = lcs[i]!;
      const next = lcs[i + 1]!;
      row[j] =
        a[i] === b[j] ? next[j + 1]! + 1 : Math.max(next[j]!, row[j + 1]!);
    }
  }
  const lines: string[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      i += 1;
      j += 1;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      lines.push(`-${a[i]!}`);
      i += 1;
    } else {
      lines.push(`+${b[j]!}`);
      j += 1;
    }
  }
  for (; i < a.length; i += 1) lines.push(`-${a[i]!}`);
  for (; j < b.length; j += 1) lines.push(`+${b[j]!}`);
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
  // Compare canonically: `current.content` is re-serialised JSON while `desired`
  // is the raw file, so a byte comparison never matches for a commented HuJSON
  // and would report a change on every --dry-run.
  const canonicalBefore = canonicalizePolicy(current.content);
  const canonicalAfter = canonicalizePolicy(desired);
  const diff = simpleDiff(canonicalBefore, canonicalAfter);
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
    ? join(backupDir, `${basename(file)}.bak`)
    : `${file}.bak`;
  if (backupDir) {
    const { mkdirSync } = await import("node:fs");
    try {
      mkdirSync(backupDir, { recursive: true });
    } catch {
      // best-effort
    }
  }
  // Back up the HuJSON form so comments and formatting survive a rollback.
  const currentRaw = await api.getPolicyHuJson();
  await writeFile(backup, currentRaw.content, "utf8");
  await api.updatePolicy(desired, current.etag);
  const verified = await api.getPolicy();
  if (!verified.json)
    throw new Error("POLICY_VERIFY_FAILED: API returned no policy");
  // Assert the write actually landed: `verified.json` is only checked for
  // presence otherwise, which can never fail and hides rejected writes.
  if (canonicalizePolicy(verified.content) !== canonicalAfter)
    throw new Error(
      "POLICY_VERIFY_FAILED: the policy read back after the write does not match the requested policy",
    );
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
  } catch (error) {
    // Distinguish "cannot read settings" from "HTTPS is off": treating a
    // transport/permission error as "disabled" turns an accurate 403 into a
    // confusing PATCH failure further down.
    if (
      error instanceof ApiError &&
      (error.status === 401 || error.status === 403)
    ) {
      return {
        provisioned: false,
        warnings: [
          "HTTPS_SETTINGS_UNVERIFIABLE: cannot read tailnet settings with this credential (missing 'all' scope); skipping the HTTPS check",
        ],
      };
    }
    throw error;
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
