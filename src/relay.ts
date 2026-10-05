import net from "node:net";
import { readFileSync, existsSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { parse as parseJsonc } from "jsonc-parser";

export interface RelayMapping {
  listenPort: number;
  targetHost: string;
  targetPort: number;
  listenHost?: string | undefined;
  serve?: boolean | undefined;
  funnel?: boolean | undefined;
  user?: string | undefined;
  password?: string | undefined;
  database?: string | undefined;
  name?: string | undefined;
  accessMode?: string | undefined;
}

export interface RelayOptions {
  listenPort: number;
  targetHost: string;
  targetPort: number;
  listenHost?: string | undefined;
  /** Timeout (ms) for connecting to the target. Default: 5000. */
  connectTimeoutMs?: number | undefined;
  onConnection?: ((clientAddr: string) => void) | undefined;
  onError?: ((error: Error) => void) | undefined;
}

export interface RelayInstance {
  server: net.Server;
  close: () => Promise<void>;
  connectionsCount: () => Promise<number>;
}

export type RelayEndpointState =
  "up" | "down" | "bind-failed" | "auth-failed" | "unknown";

export interface RelayEndpointStatus {
  mapping: RelayMapping;
  state: RelayEndpointState;
  instance?: RelayInstance | undefined;
  lastError?: string | undefined;
}

export interface MultiRelayInstance {
  relays: Array<{
    mapping: RelayMapping;
    instance: RelayInstance;
  }>;
  /** Present when allowPartial=true and some binds failed. */
  degraded?: boolean | undefined;
  failed?: Array<{ mapping: RelayMapping; error: string }> | undefined;
  close: () => Promise<void>;
}

/**
 * Parse a host:port token that may be a bare IPv4/name, an IPv6 address in
 * [::1] brackets, or a plain "host:port" / "[host]:port" pair.
 *
 * Returns { host, port } where port is NaN when no port segment is present.
 *
 * Supported tokens:
 *  "5432"              → host="" port=5432
 *  "192.168.1.1:5432"  → host="192.168.1.1" port=5432
 *  "[fd7a::1]:5432"    → host="fd7a::1" port=5432
 *  "[::1]:5432"        → host="::1" port=5432
 */
export function isValidPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

function splitHostPort(token: string): { host: string; port: number } {
  const trimmed = token.trim();
  // IPv6 bracketed: [host]:port
  const ipv6Match = /^\[([^\]]+)\]:(\d+)$/.exec(trimmed);
  if (ipv6Match) {
    return { host: ipv6Match[1]!, port: Number(ipv6Match[2]) };
  }
  // Bare IPv6 in brackets without port: [host]
  const ipv6NoPort = /^\[([^\]]+)\]$/.exec(trimmed);
  if (ipv6NoPort) {
    return { host: ipv6NoPort[1]!, port: NaN };
  }
  // host:port (IPv4 or hostname)
  const lastColon = trimmed.lastIndexOf(":");
  if (lastColon !== -1) {
    const maybePort = Number(trimmed.slice(lastColon + 1));
    if (Number.isFinite(maybePort)) {
      return { host: trimmed.slice(0, lastColon), port: maybePort };
    }
  }
  // Bare port number or bare hostname (no port)
  const bareNum = Number(trimmed);
  if (Number.isFinite(bareNum)) return { host: "", port: bareNum };
  return { host: trimmed, port: NaN };
}

/**
 * Parse a relay mapping string. Supported formats:
 *   "listenPort:targetPort"                     (2-token, no host separator ambiguity)
 *   "listenPort:targetHost:targetPort"
 *   "listenHost:listenPort:targetHost:targetPort"
 *
 * IPv6 addresses must be bracketed: "[fd7a::1]:5432" counts as one token.
 *
 * The parser first resolves bracketed IPv6 tokens, then splits on remaining
 * colons — so "[::1]:5432:10.0.0.1:5432" works as expected.
 *
 * B9 fix: full IPv6 support via bracket notation.
 */
export function parseRelayMapping(
  mapStr: string,
  defaultTargetHost = "127.0.0.1",
): RelayMapping {
  const raw = mapStr.trim();

  // Tokenise the mapping string into "atoms".  An atom is one of:
  //   - A bracketed IPv6+port token: "[addr]:port" → { host: "addr", port: N }
  //   - A bracketed IPv6 bare token: "[addr]"      → { host: "addr", port: NaN }
  //   - A plain numeric token:       "5432"        → { host: "", port: 5432 }
  //   - A hostname/IPv4 token:       "db.host"     → { host: "db.host", port: NaN }
  //
  // We extract atoms by scanning left-to-right, respecting [ ] brackets.

  type Atom =
    | { kind: "port"; value: number }
    | { kind: "hostport"; host: string; port: number }
    | { kind: "host"; value: string };

  const atoms: Atom[] = [];
  let pos = 0;

  while (pos < raw.length) {
    if (raw[pos] === "[") {
      // Bracketed IPv6: "[addr]" or "[addr]:port"
      const close = raw.indexOf("]", pos);
      if (close === -1)
        throw new Error(
          `RELAY_MAP_INVALID: unclosed "[" in mapping "${mapStr}"`,
        );
      const host = raw.slice(pos + 1, close);
      pos = close + 1;
      if (raw[pos] === ":") {
        pos++;
        const start = pos;
        while (pos < raw.length && raw[pos] !== ":") pos++;
        const port = Number(raw.slice(start, pos));
        if (!Number.isFinite(port) || port <= 0 || port > 65535)
          throw new Error(
            `RELAY_MAP_INVALID: invalid port after "[${host}]" in "${mapStr}"`,
          );
        atoms.push({ kind: "hostport", host, port });
      } else {
        atoms.push({ kind: "host", value: host });
      }
      if (pos < raw.length && raw[pos] === ":") pos++; // consume separator
    } else {
      // Scan to next colon
      const start = pos;
      while (pos < raw.length && raw[pos] !== ":") pos++;
      const token = raw.slice(start, pos);
      pos++; // consume colon or EOF
      const num = Number(token);
      if (
        Number.isFinite(num) &&
        num > 0 &&
        num <= 65535 &&
        token.trim() !== ""
      ) {
        atoms.push({ kind: "port", value: num });
      } else if (
        token.includes(".") ||
        token.includes("-") ||
        /[a-zA-Z]/.test(token)
      ) {
        atoms.push({ kind: "host", value: token });
      } else if (token.trim() !== "") {
        throw new Error(
          `RELAY_MAP_INVALID: unrecognized token "${token}" in mapping "${mapStr}"`,
        );
      }
    }
  }

  // Now interpret the atom sequence:
  //   [port, port]            → listenPort:targetPort
  //   [port, hostport]        → listenPort:[targetHost]:targetPort
  //   [port, host, port]      → listenPort:targetHost:targetPort
  //   [hostport, port]        → [listenHost]:listenPort:targetPort
  //   [hostport, hostport]    → [listenHost]:listenPort:[targetHost]:targetPort
  //   [hostport, host, port]  → [listenHost]:listenPort:targetHost:targetPort
  //   [host, port, host, port] / [host, port, hostport] → listenHost:listenPort:targetHost:targetPort

  const invalidMapping = (): never => {
    throw new Error(
      `RELAY_MAP_INVALID: unrecognized mapping format "${mapStr}"`,
    );
  };

  if (atoms.length === 2) {
    const [a0, a1] = atoms as [Atom, Atom];
    if (a0.kind === "port" && a1.kind === "port") {
      // listenPort:targetPort
      return {
        listenPort: a0.value,
        targetHost: defaultTargetHost,
        targetPort: a1.value,
      };
    }
    if (a0.kind === "port" && a1.kind === "hostport") {
      // listenPort:[host]:port
      return { listenPort: a0.value, targetHost: a1.host, targetPort: a1.port };
    }
    if (a0.kind === "hostport" && a1.kind === "hostport") {
      // [listenHost]:listenPort:[targetHost]:targetPort
      return {
        listenHost: a0.host,
        listenPort: a0.port,
        targetHost: a1.host,
        targetPort: a1.port,
      };
    }
    if (a0.kind === "hostport" && a1.kind === "port") {
      // [listenHost]:listenPort:targetPort
      return {
        listenHost: a0.host,
        listenPort: a0.port,
        targetHost: defaultTargetHost,
        targetPort: a1.value,
      };
    }
    return invalidMapping();
  }

  if (atoms.length === 3) {
    const [a0, a1, a2] = atoms as [Atom, Atom, Atom];
    if (a0.kind === "port" && a1.kind === "host" && a2.kind === "port") {
      // listenPort:targetHost:targetPort
      return {
        listenPort: a0.value,
        targetHost: a1.value,
        targetPort: a2.value,
      };
    }
    if (a0.kind === "hostport" && a1.kind === "host" && a2.kind === "port") {
      // [listenHost]:listenPort:targetHost:targetPort (target no-bracket)
      return {
        listenHost: a0.host,
        listenPort: a0.port,
        targetHost: a1.value,
        targetPort: a2.value,
      };
    }
    if (a0.kind === "host" && a1.kind === "port" && a2.kind === "hostport") {
      // listenHost:listenPort:[targetHost]:targetPort
      return {
        listenHost: a0.value,
        listenPort: a1.value,
        targetHost: a2.host,
        targetPort: a2.port,
      };
    }
    return invalidMapping();
  }

  if (atoms.length === 4) {
    const [a0, a1, a2, a3] = atoms as [Atom, Atom, Atom, Atom];
    // listenHost:listenPort:targetHost:targetPort (all plain)
    if (
      a0.kind === "host" &&
      a1.kind === "port" &&
      a2.kind === "host" &&
      a3.kind === "port"
    ) {
      return {
        listenHost: a0.value,
        listenPort: a1.value,
        targetHost: a2.value,
        targetPort: a3.value,
      };
    }
    return invalidMapping();
  }

  return invalidMapping();
}

/**
 * Load relay config from a JSON or JSONC file.
 *
 * B3 fix: uses jsonc-parser instead of a regex-based strip that corrupts
 * connection strings containing "//".
 */
export function loadRelayConfigFile(filePath: string): RelayMapping[] {
  const resolved = resolvePath(process.cwd(), filePath);
  if (!existsSync(resolved)) {
    throw new Error(
      `RELAY_CONFIG_FILE_NOT_FOUND: file not found at ${resolved}`,
    );
  }
  const raw = readFileSync(resolved, "utf8");

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const errors: any[] = [];

  const parsed = parseJsonc(raw, errors) as unknown;
  if (errors.length > 0) {
    throw new Error(
      `RELAY_CONFIG_PARSE_ERROR: ${errors.map((e) => e.error.message).join("; ")} in ${resolved}`,
    );
  }

  const rawList: unknown[] = Array.isArray(parsed)
    ? parsed
    : typeof parsed === "object" &&
        parsed !== null &&
        "relays" in parsed &&
        Array.isArray((parsed as Record<string, unknown>).relays)
      ? (parsed as { relays: unknown[] }).relays
      : [parsed];

  const mappings: RelayMapping[] = [];
  for (const item of rawList) {
    if (typeof item === "string") {
      mappings.push(parseRelayMapping(item));
    } else if (typeof item === "object" && item !== null) {
      const obj = item as Record<string, unknown>;
      const listenPort = Number(obj.listen ?? obj.listenPort ?? obj.port);
      let targetHost = String(obj.targetHost ?? obj.host ?? "127.0.0.1");
      let targetPort = Number(obj.targetPort ?? obj.target);
      if (typeof obj.target === "string" && obj.target.includes(":")) {
        const { host, port } = splitHostPort(obj.target);
        targetHost = host;
        targetPort = port;
      }
      // Number.isFinite alone accepts 0, -1, 99999 and 8080.5, which then
      // reach server.listen / net.connect as an opaque EINVAL.
      if (!isValidPort(listenPort) || !isValidPort(targetPort)) {
        throw new Error(
          `RELAY_CONFIG_ITEM_INVALID: listen and target ports must be integers in 1-65535, got ${listenPort}/${targetPort} in ${JSON.stringify(item)}`,
        );
      }
      mappings.push({
        listenPort,
        targetHost,
        targetPort,
        listenHost: obj.listenHost ? String(obj.listenHost) : undefined,
        serve: Boolean(obj.serve),
        funnel: Boolean(obj.funnel),
        user: obj.user !== undefined ? String(obj.user) : undefined,
        password: obj.password !== undefined ? String(obj.password) : undefined,
        database: obj.database !== undefined ? String(obj.database) : undefined,
        name: obj.name !== undefined ? String(obj.name) : undefined,
        accessMode:
          obj.accessMode !== undefined ? String(obj.accessMode) : undefined,
      });
    }
  }
  return mappings;
}

/**
 * Start a single TCP relay.
 *
 * Fixes applied:
 * - Default listenHost changed to "127.0.0.1" (explicit 0.0.0.0 to expose)
 * - socket.setKeepAlive(true, 30_000) on both sockets (bug #3 in plan)
 * - socket.setNoDelay(true) on both sockets (bug #5 in plan / P1)
 * - connectTimeoutMs (default 5000) applied via socket.setTimeout (bug #4)
 * - Graceful end() before destroy() when no bytes have passed (bug #6 / P1)
 */
export function startRelay(options: RelayOptions): Promise<RelayInstance> {
  return new Promise((resolve, reject) => {
    const {
      listenPort,
      targetHost,
      targetPort,
      listenHost = "127.0.0.1",
      connectTimeoutMs = 5_000,
      onConnection,
      onError,
    } = options;

    const sockets = new Set<net.Socket>();
    const server = net.createServer((clientSocket) => {
      sockets.add(clientSocket);
      clientSocket.once("close", () => sockets.delete(clientSocket));
      const clientAddr = `${clientSocket.remoteAddress ?? "unknown"}:${clientSocket.remotePort ?? 0}`;
      if (onConnection) {
        onConnection(clientAddr);
      }

      // Enable keepalive so NAT/firewall idle-flow drops are detected quickly.
      clientSocket.setKeepAlive(true, 30_000);
      // Disable Nagle to avoid latency accumulation on small Postgres messages.
      clientSocket.setNoDelay(true);

      let bytesSent = 0;

      const targetSocket = net.connect({
        host: targetHost,
        port: targetPort,
      });

      // Apply connect timeout before the connection is established.
      targetSocket.setTimeout(connectTimeoutMs);
      targetSocket.once("timeout", () => {
        const err = new Error(
          `RELAY_CONNECT_TIMEOUT: could not connect to ${targetHost}:${targetPort} within ${connectTimeoutMs}ms`,
        );
        if (onError) onError(err);
        // No bytes yet → graceful end so client gets a proper EOF.
        if (bytesSent === 0) {
          clientSocket.end();
          targetSocket.destroy();
        } else {
          clientSocket.destroy();
          targetSocket.destroy();
        }
      });

      targetSocket.once("connect", () => {
        // Clear connect timeout; enable keepalive + noDelay on live socket.
        targetSocket.setTimeout(0);
        targetSocket.setKeepAlive(true, 30_000);
        targetSocket.setNoDelay(true);
      });

      clientSocket.pipe(targetSocket);
      targetSocket.pipe(clientSocket);

      clientSocket.on("data", () => {
        bytesSent++;
      });

      const handleErr = (err: Error) => {
        if (onError) onError(err);
        if (bytesSent === 0) {
          clientSocket.end();
          targetSocket.destroy();
        } else {
          clientSocket.destroy();
          targetSocket.destroy();
        }
      };

      clientSocket.on("error", handleErr);
      targetSocket.on("error", handleErr);

      clientSocket.on("close", () => {
        targetSocket.destroy();
      });
      targetSocket.on("close", () => {
        clientSocket.destroy();
      });
    });

    const onListenError = (err: Error): void => {
      reject(err);
    };
    server.once("error", onListenError);

    server.listen(listenPort, listenHost, () => {
      // The promise is settled now: a later `error` must be reported, not
      // silently swallowed by a reject() that can no longer take effect
      // (which would also leave the next `error` unhandled and crash the CLI).
      server.removeListener("error", onListenError);
      server.on("error", (err: Error) => {
        if (onError) onError(err);
      });
      resolve({
        server,
        close: () =>
          new Promise<void>((res, rej) => {
            server.close((err) => (err ? rej(err) : res()));
            // `server.close` only stops accepting: the callback waits for every
            // open connection, and relay clients hold long-lived sessions, so
            // destroy them explicitly or shutdown hangs after Ctrl+C.
            for (const socket of sockets) socket.destroy();
            sockets.clear();
          }),
        connectionsCount: () =>
          new Promise<number>((res, rej) => {
            server.getConnections((err, count) =>
              err ? rej(err) : res(count),
            );
          }),
      });
    });
  });
}

/**
 * Start multiple TCP relays from a list of mappings.
 *
 * Degraded mode (allowPartial=true, recommended for long-running daemons):
 * - Binds what can be bound; collects failures instead of throwing.
 * - Returns { degraded: true, failed: [...] } when some binds failed.
 * - Caller can expose this via an envelope with degraded state.
 *
 * Strict mode (default, allowPartial=false):
 * - Original all-or-nothing behaviour: one failure rolls back all.
 * - Suitable for one-shot invocations where config correctness is required.
 */
export async function startMultiRelay(
  mappings: RelayMapping[],
  callbacks?: {
    onConnection?: (mapping: RelayMapping, clientAddr: string) => void;
    onError?: (mapping: RelayMapping, error: Error) => void;
  },
  opts?: {
    allowPartial?: boolean;
    connectTimeoutMs?: number;
  },
): Promise<MultiRelayInstance> {
  const allowPartial = opts?.allowPartial ?? false;
  const connectTimeoutMs = opts?.connectTimeoutMs;

  const started: Array<{ mapping: RelayMapping; instance: RelayInstance }> = [];
  const failed: Array<{ mapping: RelayMapping; error: string }> = [];

  for (const m of mappings) {
    try {
      const instance = await startRelay({
        listenPort: m.listenPort,
        targetHost: m.targetHost,
        targetPort: m.targetPort,
        listenHost: m.listenHost ?? "127.0.0.1",
        connectTimeoutMs,
        onConnection: (addr) => callbacks?.onConnection?.(m, addr),
        onError: (err) => callbacks?.onError?.(m, err),
      });
      started.push({ mapping: m, instance });
    } catch (error) {
      if (!allowPartial) {
        // Roll back already-started relays and re-throw.
        await Promise.all(
          started.map((s) => s.instance.close().catch(() => {})),
        );
        throw error;
      }
      failed.push({
        mapping: m,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const degraded = failed.length > 0;
  return {
    relays: started,
    ...(degraded ? { degraded: true, failed } : {}),
    close: async () => {
      await Promise.all(started.map((s) => s.instance.close()));
    },
  };
}
