import { readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function packageVersion(): string {
  try {
    const here = fileURLToPath(new URL(".", import.meta.url));
    const pkg = JSON.parse(
      readFileSync(resolvePath(here, "..", "package.json"), "utf8"),
    ) as { version?: string };
    if (pkg.version) return pkg.version;
  } catch {
    // Fall through to a safe default when package.json is not reachable.
  }
  return "0.0.0";
}
