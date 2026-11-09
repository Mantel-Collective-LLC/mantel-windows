import { describe, expect, it } from "vitest";
import { createTranslator } from "../shared/core/i18n";
import { EXPIRING_SOON_MS, paidTexts, paidTime, remainingOf } from "../shared/ui/src/lib/paid-time";

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const NOW = Date.parse("2026-10-22T12:00:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();

const de = createTranslator("de", "de-DE");
const en = createTranslator("en", "en-GB");

describe("paid time state", () => {
  it("is active with more than 7 days left, ring on a 30-day scale", () => {
    const paid = paidTime(iso(NOW + 23 * DAY), iso(NOW + 30 * DAY), NOW);
    expect(paid).toMatchObject({ state: "active", remainingMs: 23 * DAY, graceRemainingMs: null });
    expect(paid?.progress).toBeCloseTo(23 / 30);
    expect(paidTime(iso(NOW + 400 * DAY), null, NOW)?.progress).toBe(1);
  });

  it("is expiring at 7 days or less", () => {
    expect(paidTime(iso(NOW + EXPIRING_SOON_MS + MINUTE), null, NOW)?.state).toBe("active");
    expect(paidTime(iso(NOW + EXPIRING_SOON_MS), null, NOW)?.state).toBe("expiring");
    expect(paidTime(iso(NOW + 5 * HOUR), null, NOW)?.state).toBe("expiring");
  });

  it("is in the grace period only while the API's graceUntil is ahead", () => {
    const grace = paidTime(iso(NOW - 2 * DAY), iso(NOW + 5 * DAY), NOW);
    expect(grace).toMatchObject({ state: "grace", graceRemainingMs: 5 * DAY });
    expect(grace?.progress).toBeCloseTo(5 / 7);
    expect(paidTime(iso(NOW - 12 * DAY), iso(NOW - 5 * DAY), NOW)).toMatchObject({ state: "expired", progress: 0 });
  });

  it("does not invent a grace period the server did not report", () => {
    expect(paidTime(iso(NOW - 2 * DAY), undefined, NOW)).toMatchObject({ state: "expired", graceUntil: null });
    expect(paidTime(iso(NOW - 2 * DAY), iso(NOW - 3 * DAY), NOW)).toMatchObject({ state: "expired", graceUntil: null });
    expect(paidTime(iso(NOW - 2 * DAY), "kein Datum", NOW)?.state).toBe("expired");
  });

  it("is new (not expired, no grace) for an account that never had time, but only while nothing is paid", () => {
    const fresh = paidTime(iso(NOW - HOUR), iso(NOW + 7 * DAY - HOUR), NOW, true);
    expect(fresh).toMatchObject({ state: "new", graceUntil: null, progress: 0 });
    expect(paidTime(iso(NOW + 30 * DAY), null, NOW, true)?.state).toBe("active");
    expect(paidTexts(fresh!, en)).toMatchObject({ title: "No time yet", state: "No time yet", ring: null });
    expect(paidTexts(fresh!, de).note).toContain("Gutschein");
  });

  it("rejects a paidUntil that is not a date", () => {
    expect(paidTime("bald", null, NOW)).toBeNull();
  });
});

describe("remaining time", () => {
  it("rounds down to the largest whole unit, never promising more than is paid", () => {
    expect(remainingOf(23 * DAY + 20 * HOUR)).toEqual({ unit: "days", count: 23 });
    expect(remainingOf(DAY)).toEqual({ unit: "days", count: 1 });
    expect(remainingOf(DAY - 1)).toEqual({ unit: "hours", count: 23 });
    expect(remainingOf(5 * HOUR + 40 * MINUTE)).toEqual({ unit: "hours", count: 5 });
    expect(remainingOf(HOUR - 1)).toEqual({ unit: "minutes", count: 60 });
    expect(remainingOf(12 * MINUTE + 1)).toEqual({ unit: "minutes", count: 13 });
    expect(remainingOf(1)).toEqual({ unit: "minutes", count: 1 });
  });
});

describe("paid time texts", () => {
  it("says how long and until when, in German and English", () => {
    const paid = paidTime("2026-11-14T12:00:00.000Z", null, NOW)!;
    expect(paidTexts(paid, de)).toEqual({
      title: "Noch 23 Tage",
      subtitle: "bezahlt bis 14.11.2026",
      state: "Aktiv",
      note: null,
      ring: { value: "23", unit: "Tage" },
    });
    expect(paidTexts(paid, en)).toMatchObject({ title: "23 days left", subtitle: "paid until 14/11/2026", state: "Active" });
  });

  it("uses singular, hours and minutes when little is left", () => {
    expect(paidTexts(paidTime(iso(NOW + DAY + HOUR), null, NOW)!, de)).toMatchObject({
      title: "Noch 1 Tag",
      state: "Läuft bald ab",
      note: de.t.paid.expiringNote,
      ring: { value: "1", unit: "Tag" },
    });
    expect(paidTexts(paidTime(iso(NOW + 5 * HOUR + 20 * MINUTE), null, NOW)!, de).title).toBe("Noch 5 Stunden");
    expect(paidTexts(paidTime(iso(NOW + HOUR), null, NOW)!, en).title).toBe("1 hour left");
    expect(paidTexts(paidTime(iso(NOW + 42 * MINUTE), null, NOW)!, de).title).toBe("Noch 42 Minuten");
  });

  it("names the end of the grace period only when the API sent one", () => {
    const grace = paidTexts(paidTime("2026-10-20T12:00:00.000Z", "2026-10-27T12:00:00.000Z", NOW)!, de);
    expect(grace).toMatchObject({
      title: "Abgelaufen",
      subtitle: "abgelaufen am 20.10.2026",
      state: "Kulanzfrist",
      note: "Kulanzfrist bis 27.10.2026. Danach wird der Zugang gesperrt.",
      ring: null,
    });
    const expired = paidTexts(paidTime("2026-10-20T12:00:00.000Z", undefined, NOW)!, en);
    expect(expired).toMatchObject({ title: "Expired", state: "Expired", note: en.t.paid.expiredNote, ring: null });
  });
});
