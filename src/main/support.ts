import { IS_DEBUG } from "./flavor";
import { ApiError } from "./api/client";
import { deviceKeyFromPkcs8, describeSupportError, newDeviceKey, SupportKeyError, SupportService, type DeviceKey, type SupportKeyStore, type TicketTransport, type UserPlatform } from "../../shared/core/support";
import type { Store } from "./store";

export type SecretStore = Pick<Store, "getSecrets" | "setSecrets" | "encryptionAvailable">;

export function desktopKeyStore(store: SecretStore): SupportKeyStore {
  let cached: { pkcs8: string; key: DeviceKey } | null = null;
  return {
    async load() {
      const pkcs8 = store.getSecrets().ticketKey;
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
      if (!store.encryptionAvailable) throw new SupportKeyError();
      const generated = await newDeviceKey(true);
      if (!generated.pkcs8) throw new SupportKeyError();
      const pkcs8 = generated.pkcs8;
      try {
        store.setSecrets({ ...store.getSecrets(), ticketKey: pkcs8 });
      } catch {
        throw new SupportKeyError();
      }
      cached = { pkcs8, key: await deviceKeyFromPkcs8(pkcs8) };
      return cached.key;
    },
    async clear() {
      cached = null;
      const secrets = store.getSecrets();
      if (secrets.ticketKey) store.setSecrets({ ...secrets, ticketKey: null });
    },
  };
}

export function desktopPlatform(platform: NodeJS.Platform = process.platform): UserPlatform {
  return platform === "darwin" ? "macos" : platform === "linux" ? "linux" : "windows";
}

export function supportError(error: unknown): unknown {
  const failure = describeSupportError(error, { debug: IS_DEBUG });
  if (!failure) return error;
  return new ApiError(failure.message, failure.code, failure.status, {
    ...(failure.apiCode ? { apiCode: failure.apiCode } : {}),
    ...(failure.serverMessage ? { serverMessage: failure.serverMessage } : {}),
  });
}

export function createDesktopSupport(options: { store: SecretStore; transport: TicketTransport; platform?: UserPlatform }): SupportService {
  return new SupportService({ transport: options.transport, keys: desktopKeyStore(options.store), platform: options.platform ?? desktopPlatform() });
}
