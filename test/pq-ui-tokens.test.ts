import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

describe("PQ UI components", () => {
  it("use no raw white/black colours", () => {
    for (const file of ["ui/quantum-badge.tsx", "ui/pq-setting-row.tsx", "ui/pq-error-actions.tsx"]) {
      const source = readFileSync(path.join(__dirname, "../shared/ui/src", file), "utf8");
      expect(source, file).not.toMatch(/\b(bg|text|border)-(white|black)\b/);
    }
  });
});
