import { connect } from "node:net";

export type EndpointKind = "tls" | "tcp";

export function tcpConnect(
  host: string,
  port: number,
  timeoutMs: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host, port, timeout: timeoutMs });
    socket.once("connect", () => {
      socket.destroy();
      resolve();
    });
    socket.once("error", (error) => {
      socket.destroy();
      reject(error);
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error(`TCP connect to ${host}:${port} timed out`));
    });
  });
}

export interface EndpointVerification {
  ok: boolean;
  verifiedPorts: number[];
  attempts: number;
  lastError?: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Polls every requested port until a real connection succeeds or the deadline
 * passes. `tls` performs a full HTTPS handshake (TLS + HTTP response, any
 * status counts: a 4xx/5xx still proves the funnel edge terminated the
 * connection); `tcp` performs a raw TCP connect.
 */
export async function verifyEndpointReachable(
  hostname: string,
  ports: number[],
  kind: EndpointKind,
  timeoutSeconds: number,
): Promise<EndpointVerification> {
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) {
    throw new Error(
      `VERIFY_TIMEOUT_INVALID: expected a positive number of seconds, got ${timeoutSeconds}`,
    );
  }
  const deadline = Date.now() + timeoutSeconds * 1000;
  const pending = new Set(ports);
  let attempts = 0;
  let lastError: string | undefined;
  while (pending.size > 0 && Date.now() < deadline) {
    for (const port of [...pending]) {
      attempts += 1;
      try {
        if (kind === "tls") {
          await probeTls(hostname, port);
        } else {
          await tcpConnect(hostname, port, 10_000);
        }
        pending.delete(port);
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
      }
    }
    if (pending.size > 0) {
      const wait = Math.min(10_000, deadline - Date.now());
      if (wait > 0) await sleep(wait);
    }
  }
  return {
    ok: pending.size === 0,
    verifiedPorts: ports.filter((port) => !pending.has(port)),
    attempts,
    ...(lastError ? { lastError } : {}),
  };
}

/**
 * A HEAD probe bounded by an abort timeout. The timer is always cleared and the
 * response body always released, otherwise every failed attempt leaks a live
 * 10s timer that keeps the event loop running.
 */
async function probeTls(hostname: string, port: number): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(`https://${hostname}:${port}/`, {
      method: "HEAD",
      redirect: "manual",
      signal: controller.signal,
    });
    await response.body?.cancel();
  } finally {
    clearTimeout(timer);
  }
}
