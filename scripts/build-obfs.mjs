import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = path.join(root, "obfs-sidecar");
const target = process.argv[2];
if (target !== "win" && target !== "mac") {
  console.error("Aufruf: node scripts/build-obfs.mjs <win|mac>");
  process.exit(2);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: "inherit", ...options });
  if (result.status !== 0) {
    console.error(`${command} ${args.join(" ")} fehlgeschlagen (${result.status ?? result.error?.message})`);
    process.exit(1);
  }
}

function build(goos, goarch, output) {
  run("go", ["build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -buildid=", "-o", output, "."], {
    cwd: source,
    env: { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: "0", GOFLAGS: "-mod=readonly" },
  });
}

if (target === "win") {
  const out = path.join(root, "build", "obfs");
  mkdirSync(out, { recursive: true });
  const binary = path.join(out, "mantel-obfs.exe");
  build("windows", "amd64", binary);
  console.log(`mantel-obfs (windows/amd64): ${binary}`);
  process.exit(0);
}

const out = path.join(root, "build", "mac", "obfs");
mkdirSync(out, { recursive: true });
const binaries = [];
for (const [goarch, name] of [
  ["arm64", "mantel-obfs-arm64"],
  ["amd64", "mantel-obfs-x64"],
]) {
  const binary = path.join(out, name);
  build("darwin", goarch, binary);
  binaries.push(binary);
}
if (process.platform !== "darwin") {
  console.log(`mantel-obfs für darwin/arm64 und darwin/amd64 gebaut (${out}); universal + Signatur nur auf einem Mac.`);
  process.exit(0);
}
const universal = path.join(out, "mantel-obfs");
rmSync(universal, { force: true });
run("lipo", ["-create", "-output", universal, ...binaries]);
run("codesign", ["--force", "--sign", "-", "--identifier", "net.mantel.obfs", universal]);
run("codesign", ["--verify", "--strict", universal]);
for (const binary of binaries) rmSync(binary, { force: true });
console.log(`mantel-obfs (universal, ad-hoc signiert): ${universal}`);
