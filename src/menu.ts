import { confirm, input, select } from "@inquirer/prompts";

const profiles = [
  { name: "auto (detect from environment)", value: "" },
  { name: "ci", value: "ci" },
  { name: "container", value: "container" },
  { name: "vm", value: "vm" },
  { name: "windows", value: "windows" },
  { name: "funnel-app", value: "funnel-app" },
  { name: "subnet-router", value: "subnet-router" },
  { name: "exit-node", value: "exit-node" },
  { name: "dev", value: "dev" },
];

async function profileFlag(): Promise<string[]> {
  const profile = await select({ message: "Profile", choices: profiles });
  return profile ? ["--profile", profile] : [];
}

export async function interactiveMenu(): Promise<string[]> {
  const action = await select({
    message: "What do you want to do?",
    choices: [
      { name: "Join the tailnet (deploy)", value: "deploy" },
      {
        name: "Expose a local service on the public internet (funnel)",
        value: "funnel",
      },
      { name: "Share a local service on the tailnet (serve)", value: "serve" },
      { name: "Read/configure DNS (dns)", value: "dns" },
      { name: "Sync the tailnet policy from a file (policy)", value: "policy" },
      { name: "Show local status (status)", value: "status" },
      { name: "Diagnose credential/runtime/binary (doctor)", value: "doctor" },
      { name: "Remove matching offline devices (cleanup)", value: "cleanup" },
      { name: "Update the Tailscale binary (update-bin)", value: "update-bin" },
      { name: "Print the help text", value: "help" },
      { name: "Exit", value: "exit" },
    ],
  });

  switch (action) {
    case "deploy": {
      const args = ["deploy", ...(await profileFlag())];
      const target = (
        await input({
          message:
            "Local target to expose (e.g. 3000 or localhost:8080, empty to just join)",
          default: "",
        })
      ).trim();
      if (target) args.push("--expose", target);
      const funnel = await confirm({
        message: "Expose it publicly via Funnel (requires HTTPS)?",
        default: false,
      });
      if (funnel) {
        args.push("--funnel", "--apply-policy", "--enable-https");
      } else if (target) {
        args.push("--apply-policy");
      }
      args.push("--cleanup");
      const yes = await confirm({
        message: "Approve the lifecycle side effects (--yes)?",
        default: true,
      });
      if (yes) args.push("--yes");
      return args;
    }
    case "funnel": {
      const target = (
        await input({
          message: "Local target (e.g. 4096 or http://127.0.0.1:4096)",
          default: process.env.PORT || "4096",
        })
      ).trim();
      return [
        "funnel",
        ...(await profileFlag()),
        target,
        "--yes",
        "--apply-policy",
        "--enable-https",
      ];
    }
    case "serve": {
      const target = (
        await input({
          message: "Local target (e.g. 3000 or http://127.0.0.1:3000)",
        })
      ).trim();
      const port = (
        await input({
          message: "HTTPS port on the tailnet (443 by default)",
          default: "443",
        })
      ).trim();
      return [
        "serve",
        target,
        ...(port && port !== "443" ? ["--https", port] : []),
      ];
    }
    case "dns": {
      const enable = await confirm({
        message: "Enable MagicDNS on the tailnet (needs --yes)?",
        default: false,
      });
      return ["dns", ...(enable ? ["--enable-magicdns", "--yes"] : [])];
    }
    case "policy": {
      const file = (
        await input({
          message: "Policy file path (HuJSON)",
          default: "policy.hujson",
        })
      ).trim();
      const sync = await confirm({
        message: "Sync (apply) the diff, not just diff it?",
        default: false,
      });
      const yes = await confirm({
        message: "Approve the policy write (--yes)?",
        default: true,
      });
      return [
        "policy",
        "--file",
        file,
        ...(sync ? ["--sync", ...(yes ? ["--yes"] : [])] : []),
      ];
    }
    case "status":
      return ["status"];
    case "doctor":
      return ["doctor", "--detect-credentials"];
    case "cleanup": {
      const dryRun = await confirm({
        message: "Dry-run the cleanup candidates first?",
        default: true,
      });
      if (dryRun) return ["cleanup", "--dry-run"];
      const yes = await confirm({
        message: "Actually remove matching offline devices (--yes)?",
        default: false,
      });
      return ["cleanup", ...(yes ? ["--yes"] : ["--dry-run"])];
    }
    case "update-bin": {
      const force = await confirm({
        message:
          "Force a fresh download even if the cached version runs (--force)?",
        default: false,
      });
      return ["update-bin", ...(force ? ["--force", "--yes"] : [])];
    }
    case "help":
      return ["--help"];
    case "exit":
      return [];
  }
}
