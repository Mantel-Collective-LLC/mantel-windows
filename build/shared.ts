import { resolve } from "node:path";

export const sharedDir = resolve(__dirname, "../shared");
export const rendererRoot = resolve(sharedDir, "ui");
const modules = resolve(__dirname, "../node_modules");

export const SHARED_DEPS = [
  "react",
  "react-dom",
  "motion",
  "@phosphor-icons/react",
  "clsx",
  "tailwind-merge",
  "tailwindcss",
  "@fontsource-variable/geist",
  "@fontsource-variable/geist-mono",
];

export const sharedDepAliases = SHARED_DEPS.map((name) => ({
  find: new RegExp(`^${name}(/.*)?$`),
  replacement: `${resolve(modules, name)}$1`,
}));
