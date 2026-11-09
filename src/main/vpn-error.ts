import type { ErrorCode } from "../../shared/core/contract";
import { LocalizedError, type ErrorKey, type Params } from "../../shared/core/i18n";

export class VpnError extends LocalizedError {
  constructor(
    key: ErrorKey,
    readonly code: ErrorCode,
    params?: Params,
  ) {
    super(key, params);
  }
}
