import {
  deviceKeyFromPkcs8,
  newDeviceKey,
  SupportKeyError,
  SupportService,
  type DeviceKey,
  type SupportKeyStore,
  type TicketTransport,
} from "../../shared/core/support";
import type { Invoke } from "./bridge";

export function tauriKeyStore(call: Invoke): SupportKeyStore {
  let cached: { pkcs8: string; key: DeviceKey } | null = null;
  return {
    async load() {
      const pkcs8 = (await call("support_key_load")) as string | null;
      if (!pkcs8) {
        cached = null;
        return null;
      }
      if (cached?.pkcs8 === pkcs8) return cached.key;
      try {
        cached = { pkcs8, key: await deviceKeyFromPkcs8(pkcs8) };
        return cached.key;
      } catch {
        cached = null;
        return null;
      }
    },
    async create() {
      const generated = await newDeviceKey(true);
      if (!generated.pkcs8) throw new SupportKeyError();
      try {
        await call("support_key_save", { pkcs8: generated.pkcs8 });
      } catch {
        throw new SupportKeyError();
      }
      cached = { pkcs8: generated.pkcs8, key: await deviceKeyFromPkcs8(generated.pkcs8) };
      return cached.key;
    },
    async clear() {
      cached = null;
      await call("support_key_clear");
    },
  };
}

export function tauriTicketTransport(call: Invoke): TicketTransport {
  return async (request) => {
    if (request.headers && Object.keys(request.headers).length > 0) throw new Error("ticket headers are not supported");
    return (await call("support_request", {
      method: request.method,
      path: request.path,
      query: request.query ?? null,
      body: request.body ?? null,
    })) as { status: number; body: unknown };
  };
}

export function createTauriSupport(call: Invoke): SupportService {
  return new SupportService({ transport: tauriTicketTransport(call), keys: tauriKeyStore(call), platform: "windows" });
}
