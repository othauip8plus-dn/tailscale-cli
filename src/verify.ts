import { connect } from "node:net";
import { sleep } from "./utils.js";

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
  const deadline = Date.now() + timeoutSeconds * 1000;
  const pending = new Set(ports);
  let attempts = 0;
  let lastError: string | undefined;
  while (pending.size > 0 && Date.now() < deadline) {
    for (const port of [...pending]) {
      attempts += 1;
      try {
        if (kind === "tls") {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 10_000);
          const response = await fetch(`https://${hostname}:${port}/`, {
            method: "HEAD",
            redirect: "manual",
            signal: controller.signal,
          });
          clearTimeout(timer);
          void response;
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
