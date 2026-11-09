import { z } from "zod";
import { version as appVersion } from "../../../package.json";
import { describeApiError, endsSession, errorCodeFor, parseApiErrorPayload } from "../../../shared/core/api-errors";
import { APP_VERSION_PATH, parseAppVersionInfo, type AppPlatform, type AppVersionInfo } from "../../../shared/core/app-version";
import type { AccountSettings, Device, ErrorCode, LoginOverview, PortForwardingState, SettingsPatch, VpnNode } from "../../../shared/core/contract";
import type { ProxyCreate, ProxyPatch, ProxyWithPassword, ServerProxy } from "../../../shared/core/proxy";
import { localizedOf, translate, type ErrorKey, type Language, type LocalizedMessage } from "../../../shared/core/i18n";
import { SUPPORT_API_PATH, supportRoute, supportRouteTemplate, type TicketTransport } from "../../../shared/core/support";
import { isIpLiteral } from "../net/ip";
import { normalizeHost, pinnedLookup, UnresolvedHostError } from "../net/resolve";
import { httpRequest, type HttpResponse } from "./http";
import {
  accountSchema,
  deviceSchema,
  errorSchema,
  loginSchema,
  nodesSchema,
  portForwardingSchema,
  loginsSchema,
  proxyListSchema,
  proxyWithPasswordSchema,
  registerDeviceSchema,
  registerSchema,
  settingsSchema,
  type ApiAccount,
  type RegisterDeviceResponse,
} from "./schemas";

export class ApiError extends Error {
  readonly i18n?: LocalizedMessage;
  readonly apiCode?: string;
  readonly serverMessage?: string;

  constructor(
    message: string | LocalizedMessage,
    readonly code: ErrorCode,
    readonly status: number | null,
    details: { apiCode?: string; serverMessage?: string } = {},
  ) {
    super(typeof message === "string" ? message : translate("de", message));
    if (typeof message !== "string") this.i18n = message;
    if (details.apiCode) this.apiCode = details.apiCode;
    if (details.serverMessage) this.serverMessage = details.serverMessage;
  }

  get sessionEnded(): boolean {
    return endsSession(this.status, this.apiCode);
  }
}

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export type ApiRequestRecord = {
  method: Method;
  route: string;
  status: number | null;
  durationMs: number;
  code?: ErrorCode;
  apiCode?: string;
};

export function routeTemplate(route: string): string {
  if (route === SUPPORT_API_PATH || route.startsWith(`${SUPPORT_API_PATH}/`) || route.startsWith(`${SUPPORT_API_PATH}?`)) {
    return supportRouteTemplate(route.slice(SUPPORT_API_PATH.length));
  }
  return route.replace(/^(\/api\/v1\/(?:devices|proxies)\/)[^/?#]+/, "$1:id");
}

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_TICKET_BODY_BYTES = 8 * 1024 * 1024;

type RequestOptions<T> = { body?: unknown; schema?: z.ZodType<T>; auth?: boolean | "optional"; expect?: number[]; raw?: boolean; maxBytes?: number };

function readBody(response: HttpResponse): unknown {
  const text = response.text;
  if (response.tooLarge) throw new ApiError({ key: "apiTooLarge" }, "server", response.status);
  if (text.length === 0) return null;
  try {
    return JSON.parse(text);
  } catch {
    const header = response.headers.get("content-type");
    const contentType = header ?? "";
    const blockedByCloudflare =
      response.headers.get("cf-mitigated") === "challenge" ||
      (response.headers.get("server") === "cloudflare" && contentType.includes("text/html"));
    const key: ErrorKey = blockedByCloudflare ? "apiCloudflare" : response.status === 404 ? "apiNoMantelApi" : "apiInvalidJson";
    throw new ApiError(
      { key, params: { status: response.status, contentType: header ?? { key: "apiUnknownContentType" } } },
      "server",
      response.status,
    );
  }
}

function isLoopbackName(host: string): boolean {
  return host === "localhost" || host.endsWith(".localhost");
}

export const USER_AGENT = `MantelDesktop/${appVersion} (${process.platform === "darwin" ? "macOS" : "Windows"})`;

export class ApiClient {
  onRequest: ((record: ApiRequestRecord) => void) | null = null;

  constructor(
    private readonly baseUrl: () => string,
    private readonly token: () => string | null,
    private readonly resolveHost?: (host: string) => Promise<string[]>,
    private readonly language?: () => Language,
    private readonly options: { debug?: boolean } = {},
  ) {}

  private async request<T>(method: Method, route: string, options: RequestOptions<T> = {}): Promise<T> {
    const observer = this.onRequest;
    if (!observer) return this.send(method, route, options);
    const started = performance.now();
    let status: number | null = null;
    const record = (code?: ErrorCode, apiCode?: string) => {
      try {
        observer({
          method,
          route: routeTemplate(route),
          status,
          durationMs: Math.round(performance.now() - started),
          ...(code ? { code } : {}),
          ...(apiCode ? { apiCode } : {}),
        });
      } catch {
      }
    };
    try {
      const result = await this.send(method, route, options, (value) => {
        status = value;
      });
      const received = status as number | null;
      if (options.raw && received !== null && received >= 400) {
        const apiCode = parseApiErrorPayload((result as { body?: unknown }).body)?.code;
        record(errorCodeFor(received, apiCode), apiCode);
      } else record();
      return result;
    } catch (error) {
      if (error instanceof ApiError) record(error.code, error.apiCode);
      else record("internal");
      throw error;
    }
  }

  private async send<T>(method: Method, route: string, options: RequestOptions<T>, onStatus?: (status: number) => void): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json", "User-Agent": USER_AGENT };
    if (this.language) headers["Accept-Language"] = this.language();
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    if (options.auth) {
      const token = this.token();
      if (!token && options.auth !== "optional") throw new ApiError({ key: "apiNotLoggedIn" }, "unauthorized", null);
      if (token) headers.Authorization = `Bearer ${token}`;
    }
    let url: URL;
    try {
      url = new URL(`${this.baseUrl()}${route}`);
    } catch {
      throw new ApiError({ key: "apiInvalidBaseUrl" }, "invalid", null);
    }
    const host = normalizeHost(url.hostname);
    const pin = this.resolveHost && !isIpLiteral(host) && !isLoopbackName(host);
    let response: HttpResponse;
    try {
      response = await httpRequest(url, {
        method,
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        timeoutMs: 15_000,
        maxBytes: options.maxBytes ?? MAX_BODY_BYTES,
        lookup: pin && this.resolveHost ? pinnedLookup(host, this.resolveHost) : undefined,
      });
    } catch (error) {
      if (error instanceof UnresolvedHostError && error.dnsBlocked) {
        throw new ApiError(localizedOf(error) ?? error.message, "network", null);
      }
      throw new ApiError({ key: "apiUnreachable" }, "network", null);
    }
    onStatus?.(response.status);
    if (response.status >= 300 && response.status < 400) {
      throw new ApiError({ key: "apiRedirected" }, "network", response.status);
    }
    const body = readBody(response);
    if (options.raw) return { status: response.status, body } as T;
    const expected = options.expect ?? [200];
    if (!expected.includes(response.status)) {
      const parsedError = errorSchema.safeParse(body);
      const described = describeApiError(response.status, parsedError.success ? parsedError.data : null, {
        debug: this.options.debug,
      });
      throw new ApiError(described.message, described.code, response.status, described);
    }
    if (!options.schema) return undefined as T;
    const parsed = options.schema.safeParse(body);
    if (!parsed.success) {
      throw new ApiError({ key: "apiUnexpectedFormat" }, "server", response.status);
    }
    return parsed.data;
  }

  login(code: string, totp?: string) {
    return this.request("POST", "/api/v1/auth/login", { body: { code, totp: totp ?? null }, schema: loginSchema });
  }

  register() {
    return this.request("POST", "/api/v1/auth/register", { body: {}, schema: registerSchema });
  }

  logout() {
    return this.request<undefined>("POST", "/api/v1/auth/logout", { auth: true, expect: [204, 200] });
  }

  logins(): Promise<LoginOverview> {
    return this.request("GET", "/api/v1/account/logins", { auth: true, schema: loginsSchema });
  }

  loginsSeen() {
    return this.request<undefined>("POST", "/api/v1/account/logins/seen", { auth: true, body: {}, expect: [204, 200] });
  }

  logoutOthers() {
    return this.request<undefined>("POST", "/api/v1/auth/logout-others", { auth: true, body: {}, expect: [204, 200] });
  }

  account(): Promise<ApiAccount> {
    return this.request("GET", "/api/v1/account", { auth: true, schema: accountSchema });
  }

  nodes(): Promise<VpnNode[]> {
    return this.request("GET", "/api/v1/nodes", { auth: "optional", schema: nodesSchema });
  }

  registerDevice(input: { name: string; nodeId: string; publicKey: string }): Promise<RegisterDeviceResponse> {
    return this.request("POST", "/api/v1/devices", {
      auth: true,
      body: input,
      schema: registerDeviceSchema,
      expect: [201, 200],
    });
  }

  rotateDeviceKey(id: string, publicKey: string): Promise<RegisterDeviceResponse> {
    return this.request("POST", `/api/v1/devices/${encodeURIComponent(id)}/key`, {
      auth: true,
      body: { publicKey },
      schema: registerDeviceSchema,
      expect: [200],
    });
  }

  deleteDevice(id: string) {
    return this.request<undefined>("DELETE", `/api/v1/devices/${encodeURIComponent(id)}`, {
      auth: true,
      expect: [204, 200, 404],
    });
  }

  renameDevice(id: string, name: string): Promise<Device> {
    return this.request("PATCH", `/api/v1/devices/${encodeURIComponent(id)}`, { auth: true, body: { name }, schema: deviceSchema });
  }

  async portForwarding(
    deviceId: string,
    action: "get" | "enable" | "disable" | { removePort: number } = "get",
  ): Promise<PortForwardingState> {
    const route = `/api/v1/devices/${encodeURIComponent(deviceId)}/port-forwarding`;
    const body =
      action === "get"
        ? await this.request("GET", route, { auth: true, schema: portForwardingSchema })
        : action === "enable"
          ? await this.request("POST", route, { auth: true, body: {}, schema: portForwardingSchema, expect: [201, 200] })
          : action === "disable"
            ? await this.request("DELETE", route, { auth: true, schema: portForwardingSchema, expect: [200] })
            : await this.request("DELETE", `${route}/${action.removePort}`, { auth: true, schema: portForwardingSchema, expect: [200] });
    return {
      nodeId: body.nodeId,
      city: body.city,
      available: body.available,
      reason: body.reason,
      max: body.max,
      forwards: body.forwards.map((forward) => ({ port: forward.port, host: forward.host })),
    };
  }

  setDeviceTor(deviceId: string, enabled: boolean): Promise<Device> {
    return this.request("PUT", `/api/v1/devices/${encodeURIComponent(deviceId)}/tor`, {
      auth: true,
      body: { enabled },
      schema: deviceSchema,
      expect: [200],
    });
  }

  async proxies(): Promise<ServerProxy[] | null> {
    try {
      return (await this.request("GET", "/api/v1/proxies", { auth: true, schema: proxyListSchema })).proxies;
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return null;
      throw error;
    }
  }

  createProxy(input: ProxyCreate): Promise<ProxyWithPassword> {
    return this.request("POST", "/api/v1/proxies", { auth: true, body: input, schema: proxyWithPasswordSchema, expect: [201, 200] });
  }

  updateProxy(id: string, patch: ProxyPatch): Promise<ProxyWithPassword> {
    return this.request("PATCH", `/api/v1/proxies/${encodeURIComponent(id)}`, { auth: true, body: patch, schema: proxyWithPasswordSchema });
  }

  deleteProxy(id: string) {
    return this.request<undefined>("DELETE", `/api/v1/proxies/${encodeURIComponent(id)}`, { auth: true, expect: [204, 200] });
  }

  async appVersion(platform: AppPlatform): Promise<AppVersionInfo> {
    const body = await this.request("GET", `${APP_VERSION_PATH}?platform=${platform}`, { schema: z.unknown() });
    const info = parseAppVersionInfo(body, platform);
    if (!info) throw new ApiError({ key: "apiUnexpectedFormat" }, "server", 200);
    return info;
  }

  readonly tickets: TicketTransport = async (request) =>
    this.request<{ status: number; body: unknown }>(request.method, supportRoute(request), {
      auth: true,
      raw: true,
      maxBytes: MAX_TICKET_BODY_BYTES,
      ...(request.body !== undefined ? { body: request.body } : {}),
    });

  updateSettings(patch: SettingsPatch): Promise<AccountSettings> {
    return this.request("PATCH", "/api/v1/settings", { auth: true, body: patch, schema: settingsSchema });
  }
}
