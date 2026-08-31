import { sleep } from "./utils.js";

const DOH_RESOLVERS = [
  (name: string) =>
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=A`,
  (name: string) =>
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`,
];

export interface DnsPropagationResult {
  ok: boolean;
  attempts: number;
}

async function queryDohA(url: string): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(url, {
      headers: { accept: "application/dns-json" },
      signal: controller.signal,
    });
    const json = (await response.json()) as {
      Answer?: { type: number; data: string }[];
    };
    return (json.Answer ?? []).some((record) => record.type === 1);
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function systemResolverA(hostname: string): Promise<boolean> {
  try {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const { stdout } = await promisify(execFile)(
      "getent",
      ["ahostsv4", hostname],
      { timeout: 5000 },
    );
    return Boolean(stdout.trim());
  } catch {
    return false;
  }
}

/**
 * Polls public DNS until an A record exists for the funnel hostname or the
 * deadline passes. Each round queries every DoH resolver in parallel plus the
 * system resolver, so a stale negative cache on a single resolver (e.g. a
 * cached NXDOMAIN on dns.google while cloudflare already serves the record)
 * never produces a false failure.
 */
export async function funnelPublicDnsPropagated(
  hostname: string,
  timeoutSeconds: number,
): Promise<DnsPropagationResult> {
  const deadline = Date.now() + timeoutSeconds * 1000;
  let attempts = 0;
  while (Date.now() < deadline) {
    attempts += 1;
    const results = await Promise.all([
      ...DOH_RESOLVERS.map((buildUrl) => queryDohA(buildUrl(hostname))),
      systemResolverA(hostname),
    ]);
    if (results.some(Boolean)) return { ok: true, attempts };
    const wait = Math.min(10_000, deadline - Date.now());
    if (wait > 0) await sleep(wait);
  }
  return { ok: false, attempts };
}
