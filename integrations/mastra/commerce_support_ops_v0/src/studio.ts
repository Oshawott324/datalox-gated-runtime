import { spawn } from "node:child_process";
import { join } from "node:path";

const packageRoot = process.cwd();
const executable = join(
  packageRoot,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "mastra.cmd" : "mastra",
);
const child = spawn(executable, ["dev", ...process.argv.slice(2)], {
  cwd: packageRoot,
  env: { ...process.env, DATALOX_PACKAGE_ROOT: packageRoot },
  stdio: "inherit",
});

child.once("error", (error) => {
  console.error(error);
  process.exitCode = 1;
});
child.once("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exitCode = code ?? 1;
});
