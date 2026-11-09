import type { PqErrorCode } from "../../../shared/core/contract";
import { LocalizedError, type ErrorKey } from "../../../shared/core/i18n";

const KEYS: Record<PqErrorCode, ErrorKey> = {
  pq_unsupported: "pqUnsupported",
  pq_failed: "pqFailed",
  pq_mismatch: "pqMismatch",
  pq_not_active: "pqNotActive",
};

export class PqError extends LocalizedError {
  constructor(
    readonly code: PqErrorCode,
    options?: { cause?: unknown },
  ) {
    super(KEYS[code], undefined, options);
  }
}

export type AttemptFailure =
  | "transport"
  | "protocol"
  | "mismatch"
  | "unsupported"
  | "rate_limited"
  | "retry";

export class PqAttemptError extends Error {
  constructor(
    readonly failure: AttemptFailure,
    readonly detail: string,
    readonly retryAfterS = 0,
  ) {
    super(`PQ attempt failed: ${failure} (${detail})`);
  }
}
