import { execFile as execFileCallback, spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";

import type { WorldVerdict } from "./types.js";

const execFile = promisify(execFileCallback);
const PACKAGE_ROOT = resolve(
  process.env.DATALOX_PACKAGE_ROOT ?? process.cwd(),
);
const WORLD_ROOT = join(PACKAGE_ROOT, "world");
const DATA_ROOT = resolve(
  process.env.DATALOX_DATA_DIR ?? join(PACKAGE_ROOT, ".datalox"),
);
const ACTORS = [
  { actor_id: "mastra-billing", role: "billing_specialist" },
  { actor_id: "mastra-support", role: "support_owner" },
  { actor_id: "mastra-engineering", role: "engineering_owner" },
  { actor_id: "mastra-communications", role: "communications_owner" },
] as const;

interface AdapterManifest {
  episode: { package_content_sha256: string };
}

function imageTag(): string {
  const manifest = JSON.parse(
    readFileSync(join(PACKAGE_ROOT, "DATALOX_ADAPTER.json"), "utf8"),
  ) as AdapterManifest;
  const digest = manifest.episode.package_content_sha256.replace("sha256:", "");
  return `datalox/mastra-commerce-support:${digest.slice(0, 12)}`;
}

async function runVisible(command: string, args: string[]): Promise<void> {
  await new Promise<void>((resolveRun, rejectRun) => {
    const child = spawn(command, args, { stdio: "inherit" });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolveRun();
        return;
      }
      rejectRun(
        new Error(
          `${command} exited with ${code ?? `signal ${signal ?? "unknown"}`}`,
        ),
      );
    });
  });
}

async function capture(command: string, args: string[]): Promise<string> {
  const result = await execFile(command, args, {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  return result.stdout.trim();
}

export function parsePublishedPort(output: string): number {
  const match = /^127\.0\.0\.1:(\d+)$/m.exec(output.trim());
  if (!match?.[1]) {
    throw new Error(`unexpected Docker port output: ${JSON.stringify(output)}`);
  }
  const port = Number(match[1]);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`invalid published port: ${match[1]}`);
  }
  return port;
}

export class WorldController {
  readonly runId: string;
  readonly containerName: string;
  readonly baseUrl: string;
  readonly resultsDir: string;
  private stopped = false;

  private constructor(args: {
    runId: string;
    containerName: string;
    baseUrl: string;
    resultsDir: string;
  }) {
    this.runId = args.runId;
    this.containerName = args.containerName;
    this.baseUrl = args.baseUrl;
    this.resultsDir = args.resultsDir;
  }

  static async start(): Promise<WorldController> {
    const tag = imageTag();
    await runVisible("docker", ["build", "--tag", tag, WORLD_ROOT]);

    const runId = randomUUID();
    const containerName = `datalox-mastra-${runId}`;
    const resultsDir = join(DATA_ROOT, "results", runId);
    await mkdir(resultsDir, { recursive: true });

    await capture("docker", [
      "run",
      "--detach",
      "--name",
      containerName,
      "--publish",
      "127.0.0.1::8000",
      "--env",
      `DATALOX_WORLD_PACKAGE_ACTORS=${JSON.stringify(ACTORS)}`,
      tag,
    ]);

    try {
      const published = await capture("docker", ["port", containerName, "8000/tcp"]);
      const port = parsePublishedPort(published);
      const controller = new WorldController({
        runId,
        containerName,
        baseUrl: `http://127.0.0.1:${port}`,
        resultsDir,
      });
      await controller.waitUntilHealthy();
      return controller;
    } catch (error) {
      await execFile("docker", ["rm", "--force", containerName]).catch(() => undefined);
      throw error;
    }
  }

  async finalize(): Promise<WorldVerdict> {
    const output = await capture("docker", [
      "exec",
      this.containerName,
      "python",
      "-m",
      "datalox_gated_runtime.world_package.entrypoint",
      "finalize",
      "--package-root",
      "/opt/datalox",
      "--run",
      "/var/lib/datalox/run",
      "--out",
      "/var/lib/datalox/verdict.json",
    ]);
    const verdict = JSON.parse(output) as WorldVerdict;
    validateVerdict(verdict);
    await writeFile(
      join(this.resultsDir, "verdict.json"),
      `${JSON.stringify(verdict, null, 2)}\n`,
      "utf8",
    );
    return verdict;
  }

  async writeRunResult(result: unknown): Promise<void> {
    await writeFile(
      join(this.resultsDir, "run-result.json"),
      `${JSON.stringify(result, null, 2)}\n`,
      "utf8",
    );
  }

  async stop(): Promise<void> {
    if (this.stopped) {
      return;
    }
    this.stopped = true;
    await execFile("docker", ["rm", "--force", this.containerName], {
      encoding: "utf8",
    });
  }

  private async waitUntilHealthy(): Promise<void> {
    const deadline = Date.now() + 60_000;
    let lastError = "world did not answer";
    while (Date.now() < deadline) {
      try {
        const response = await fetch(`${this.baseUrl}/health`);
        if (response.ok) {
          const body = (await response.json()) as { ok?: unknown };
          if (body.ok === true) {
            return;
          }
          lastError = `health payload was ${JSON.stringify(body)}`;
        } else {
          lastError = `health returned HTTP ${response.status}`;
        }
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
      }
      await new Promise((resolveWait) => setTimeout(resolveWait, 250));
    }
    const logs = await capture("docker", ["logs", this.containerName]).catch(
      (error: unknown) => String(error),
    );
    throw new Error(`world failed to become healthy: ${lastError}\n${logs}`);
  }
}

function validateVerdict(verdict: WorldVerdict): void {
  if (
    typeof verdict !== "object" ||
    verdict === null ||
    typeof verdict.audit?.passed !== "boolean" ||
    typeof verdict.audit.reward !== "number" ||
    verdict.audit.reward < 0 ||
    verdict.audit.reward > 1
  ) {
    throw new Error("Datalox finalizer returned an invalid verdict");
  }
}

export function dataRoot(): string {
  return DATA_ROOT;
}
