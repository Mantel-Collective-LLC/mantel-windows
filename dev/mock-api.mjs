import { createServer } from "node:http";
import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { handleTickets } from "./mock-tickets.mjs";

const PORT = Number(process.env.MOCK_PORT ?? 3101);
const HOST = process.env.MOCK_HOST ?? "127.0.0.1";
const SERVER_GENERATES_KEYS = process.env.MOCK_SERVER_KEYS === "1";
const ALLOWED_ORIGINS = new Set([
  "http://localhost:5174",
  "http://127.0.0.1:5174",
  ...(process.env.MOCK_ORIGINS ?? "").split(",").map((origin) => origin.trim()).filter(Boolean),
]);
const MAX_BODY = 16 * 1024;
const APP_VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const APP_LATEST = process.env.MOCK_APP_LATEST ?? APP_VERSION;
const APP_MINIMUM = process.env.MOCK_APP_MINIMUM ?? APP_VERSION;
const LOGIN_WINDOW_MS = 60_000;
const LOGIN_LIMIT = 5;
const DEVICE_LIMIT = 5;
const REGISTER_WINDOW_MS = 10 * 60_000;
const REGISTER_LIMIT = Number(process.env.MOCK_REGISTER_LIMIT ?? 6);
const TOTP = process.env.MOCK_TOTP ?? "";
const DAY = 86_400_000;
const BLOCKLISTS = ["ads", "trackers", "malware", "gambling", "adult", "social"];

function wgKeyPair() {
  const pair = generateKeyPairSync("x25519");
  const raw = (key, field) => Buffer.from(key.export({ format: "jwk" })[field], "base64url").toString("base64");
  return { privateKey: raw(pair.privateKey, "d"), publicKey: raw(pair.publicKey, "x") };
}

const nodes = [
  { id: "ch-zrh", city: "Zürich", country: "CH", endpointHost: "198.51.100.7", endpointPort: 51820, online: true, latencyMs: 11, postQuantum: true },
  { id: "de-fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.12", endpointPort: 51820, online: true, latencyMs: 4, postQuantum: true },
  { id: "nl-ams", city: "Amsterdam", country: "NL", endpointHost: "198.51.100.4", endpointPort: 51820, online: true, latencyMs: 8, postQuantum: false },
  { id: "se-sto", city: "Stockholm", country: "SE", endpointHost: "203.0.113.9", endpointPort: 51820, online: true, latencyMs: 19, postQuantum: false },
  { id: "is-rkv", city: "Reykjavík", country: "IS", endpointHost: "203.0.113.1", endpointPort: 51820, online: false, postQuantum: false },
  { id: "us-nyc", city: "New York", country: "US", endpointHost: "2001:db8::31", endpointPort: 51820, online: true, latencyMs: 87 },
  { id: "de-ber", city: "Berlin", country: "DE", endpointHost: "198.51.100.14", endpointPort: 51820, online: true, latencyMs: 7 },
  { id: "ch-gva", city: "Genf", country: "CH", endpointHost: "198.51.100.9", endpointPort: 51820, online: true, latencyMs: 14, status: "full" },
  { id: "fr-par", city: "Paris", country: "FR", endpointHost: "198.51.100.21", endpointPort: 51820, online: true, latencyMs: 13, status: "upgrading" },
  { id: "at-vie", city: "Wien", country: "AT", endpointHost: "198.51.100.30", endpointPort: 51820, online: true, latencyMs: 16, status: "paused" },
  { id: "gb-lon", city: "London", country: "GB", endpointHost: "203.0.113.20", endpointPort: 51820, online: true, latencyMs: 22 },
  { id: "us-lax", city: "Los Angeles", country: "US", endpointHost: "203.0.113.40", endpointPort: 51820, online: true, latencyMs: 148 },
  { id: "hk-hkg", city: "Hongkong", country: "HK", endpointHost: "203.0.113.60", endpointPort: 51820, online: true, latencyMs: 210, postQuantum: true },
  { id: "jp-tyo", city: "Tokio", country: "JP", endpointHost: "203.0.113.61", endpointPort: 51820, online: true, latencyMs: 230 },
  { id: "sg-sin", city: "Singapur", country: "SG", endpointHost: "203.0.113.62", endpointPort: 51820, online: false },
].map((node) => ({
  ...node,
  ...(node.id === "us-nyc" ? {} : { portForwarding: ["ch-zrh", "de-fra", "nl-ams"].includes(node.id) }),
  ...(["de-fra", "nl-ams", "hk-hkg"].includes(node.id) ? { obfuscation: { version: 1, port: 443, pin: randomBytes(32).toString("base64") } } : {}),
  serverPublicKey: wgKeyPair().publicKey,
}));

const localPq = process.env.MOCK_PQ_NODE ? JSON.parse(readFileSync(process.env.MOCK_PQ_NODE, "utf8")) : null;
if (localPq) {
  const match = /^127\.0\.0\.1:(\d+)$/.exec(localPq.endpoint);
  if (!match) throw new Error("MOCK_PQ_NODE: only a local node on 127.0.0.1 is allowed");
  nodes.unshift({
    id: "local-pq",
    city: "Lokaler PQ-Testnode",
    country: "DE",
    endpointHost: "127.0.0.1",
    endpointPort: Number(match[1]),
    online: true,
    latencyMs: 1,
    postQuantum: localPq.postQuantum === true,
    serverPublicKey: localPq.nodePublicKey,
  });
}

const defaultSettings = () => ({
  killSwitch: true,
  lanAccess: false,
  ipv6: true,
  dns: { ads: true, trackers: true, malware: true, gambling: false, adult: false, social: false },
});

const accounts = new Map([
  ["1234567890123456", { id: "acc_7f3a9c21", paidUntil: new Date(Date.now() + 23 * DAY).toISOString(), settings: defaultSettings(), devices: [] }],
  ["1111222233334444", { id: "acc_0b1d55e0", paidUntil: new Date(Date.now() - 2 * DAY).toISOString(), settings: defaultSettings(), devices: [] }],
  ["2222333344445555", { id: "acc_5e1a7c03", paidUntil: new Date(Date.now() + 3 * DAY + 5 * 3_600_000).toISOString(), settings: defaultSettings(), devices: [] }],
  ["3333444455556666", { id: "acc_9d42b7e8", paidUntil: new Date(Date.now() + 5 * 3_600_000 + 20 * 60_000).toISOString(), settings: defaultSettings(), devices: [] }],
  ["4444555566667777", { id: "acc_c3f08a11", paidUntil: new Date(Date.now() - 12 * DAY).toISOString(), settings: defaultSettings(), devices: [] }],
  [
    "5555666677778888",
    {
      id: "acc_4b7e2d90",
      paidUntil: new Date(Date.now() + 40 * DAY).toISOString(),
      settings: defaultSettings(),
      devices: [
        { id: "dev_a1b2c3d4e5f6", name: "Windows 7F3A", nodeId: "nl-ams", ipv4: "10.64.0.12", ipv6: null, createdOn: new Date(Date.now() - 20 * DAY).toISOString(), keyRotatedOn: new Date(Date.now() - 6 * DAY).toISOString().slice(0, 10), publicKey: "demo-1", forwardPorts: [41234] },
        { id: "dev_b2c3d4e5f6a1", name: "Android · Pixel 8", nodeId: "de-fra", ipv4: "10.64.0.13", ipv6: null, createdOn: new Date(Date.now() - 3 * DAY).toISOString(), publicKey: "demo-2", forwardPorts: [] },
        { id: "dev_c3d4e5f6a1b2", name: "Router Wohnzimmer", nodeId: "ch-zrh", ipv4: "10.64.0.14", ipv6: null, createdOn: new Date(Date.now() - 45 * DAY).toISOString(), publicKey: "demo-3", forwardPorts: [] },
      ],
      proxies: [
        { id: "px_demo1", name: "Browser", nodeId: "nl-ams", host: "198.51.100.4", port: 31080, protocol: "socks5", exit: "tor", username: "m-k7q2x9", enabled: true, status: "active" },
        { id: "px_demo2", name: "Fernseher", nodeId: "de-fra", host: "198.51.100.12", port: 38080, protocol: "http", exit: "direct", username: "m-p4n8r3", enabled: false, status: "active" },
      ],
    },
  ],
]);
const GRACE_MS = 7 * DAY;
const FORWARD_MAX = Number(process.env.MOCK_FORWARD_MAX ?? 2);
const PROXIES_OFFERED = process.env.MOCK_PROXIES !== "0";
const sessions = new Map();
const failedLogins = new Map();
const registrations = new Map();
let hostCounter = 2;

function log(request, status) {
  process.stdout.write(`${new Date().toISOString()} ${request.method} ${request.url} -> ${status}\n`);
}

function send(request, response, status, body) {
  const origin = request.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Vary", "Origin");
  }
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  if (body === undefined) {
    response.writeHead(status);
    response.end();
  } else {
    response.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
    response.end(JSON.stringify(body));
  }
  log(request, status);
}

const fail = (request, response, status, code, error, params) =>
  send(request, response, status, { code, error, ...(params ? { params } : {}) });

function readJson(request, max = MAX_BODY) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > max) {
        reject(new Error("too_large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (chunks.length === 0) return resolve(undefined);
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new Error("bad_json"));
      }
    });
    request.on("error", reject);
  });
}

function authenticate(request) {
  const header = request.headers.authorization ?? "";
  const match = header.match(/^Bearer ([A-Za-z0-9_-]{20,})$/);
  if (!match) return null;
  const code = sessions.get(match[1]);
  if (!code) return null;
  return { token: match[1], account: accounts.get(code) };
}

function publicAccount(account) {
  return {
    id: account.id,
    paidUntil: account.paidUntil,
    expired: Date.parse(account.paidUntil) <= Date.now(),
    graceUntil: new Date(Date.parse(account.paidUntil) + GRACE_MS).toISOString(),
    settings: account.settings,
    devices: account.devices.map(({ id, name, nodeId, ipv4, ipv6, createdOn, keyRotatedOn, obfsToken }) => ({ id, name, nodeId, ipv4, ipv6, createdOn, keyRotatedOn, obfsToken })),
  };
}

function publicNode({ serverPublicKey, latencyMs, ...rest }) {
  return { ...rest, latencyMs: null, ...(latencyMs !== undefined && rest.online ? { pingPort: 51821 } : {}) };
}

const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
const isWgKey = (value) => typeof value === "string" && /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$/.test(value);

function parsePatch(body) {
  if (!isRecord(body)) return null;
  const patch = {};
  for (const [key, value] of Object.entries(body)) {
    if (["killSwitch", "lanAccess", "ipv6"].includes(key)) {
      if (typeof value !== "boolean") return null;
      patch[key] = value;
      continue;
    }
    if (key === "dns") {
      if (!isRecord(value)) return null;
      const dns = {};
      for (const [list, enabled] of Object.entries(value)) {
        if (!BLOCKLISTS.includes(list) || typeof enabled !== "boolean") return null;
        dns[list] = enabled;
      }
      patch.dns = dns;
      continue;
    }
    return null;
  }
  return patch;
}

function clientKey(request) {
  return request.socket.remoteAddress ?? "unknown";
}

function rateLimited(request) {
  const now = Date.now();
  const recent = (failedLogins.get(clientKey(request)) ?? []).filter((at) => now - at < LOGIN_WINDOW_MS);
  failedLogins.set(clientKey(request), recent);
  return recent.length >= LOGIN_LIMIT;
}

async function route(request, response) {
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
  const path = url.pathname;

  if (request.method === "OPTIONS") {
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE");
    response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
    return send(request, response, 204);
  }

  if (request.method === "GET" && path === "/api/v1/app-version") {
    const platform = url.searchParams.get("platform");
    if (platform !== "windows" && platform !== "macos" && platform !== "android") {
      return fail(request, response, 400, "validation_failed", "The request is invalid.");
    }
    const latest = APP_LATEST === "none" ? null : APP_LATEST;
    return send(request, response, 200, {
      platform,
      latest,
      minimum: latest ? APP_MINIMUM : null,
      downloadUrl: "/download",
      notes: latest
        ? { de: "Schnellerer Verbindungsaufbau und Fehlerbehebungen.", en: "Faster connecting and bug fixes." }
        : null,
      sha256: latest ? "0".repeat(63) + "1" : null,
    });
  }

  let body;
  if (["POST", "PATCH"].includes(request.method ?? "")) {
    try {
      body = await readJson(request, path.startsWith("/api/v1/tickets") ? 64 * 1024 : MAX_BODY);
    } catch (error) {
      return error.message === "too_large"
        ? fail(request, response, 413, "body_too_large", "The request body is too large.")
        : fail(request, response, 400, "invalid_json", "The request body is not valid JSON.");
    }
  }

  if (request.method === "POST" && path === "/api/v1/auth/login") {
    if (rateLimited(request)) {
      return fail(request, response, 429, "rate_limited", "Too many requests. Try again in 60 seconds.", { retryAfterSeconds: 60 });
    }
    const code = isRecord(body) ? body.code : undefined;
    if (typeof code !== "string" || !/^\d{16}$/.test(code)) {
      failedLogins.get(clientKey(request)).push(Date.now());
      return fail(request, response, 400, "invalid_code", "An account number has exactly 16 digits.");
    }
    const account = accounts.get(code);
    if (!account) {
      failedLogins.get(clientKey(request)).push(Date.now());
      return fail(request, response, 401, "unknown_code", "This account number does not exist.");
    }
    if (TOTP) {
      const totp = body.totp;
      if (!("totp" in body)) return fail(request, response, 403, undefined, "Two-factor authentication is on for this account. Update the Mantel app.");
      if (totp === null || totp === "") return fail(request, response, 401, "totp_required", "Two-factor authentication is on: send the code from the authenticator app as totp.");
      if (totp !== TOTP) return fail(request, response, 401, "totp_invalid", "The two-factor code is wrong or was already used.");
    }
    const token = randomBytes(32).toString("base64url");
    sessions.set(token, code);
    return send(request, response, 200, { token, account: { id: account.id, paidUntil: account.paidUntil } });
  }

  if (request.method === "POST" && path === "/api/v1/auth/register") {
    if (body !== undefined && !isRecord(body)) {
      return fail(request, response, 400, "body_not_object", "The request body must be a JSON object.");
    }
    if (body !== undefined && Object.keys(body).length > 0) {
      return fail(request, response, 400, "unknown_field", `Unknown field: ${Object.keys(body)[0].slice(0, 40)}.`, {
        field: Object.keys(body)[0].slice(0, 40),
      });
    }
    const now = Date.now();
    const recent = (registrations.get(clientKey(request)) ?? []).filter((at) => now - at < REGISTER_WINDOW_MS);
    if (recent.length >= REGISTER_LIMIT) {
      registrations.set(clientKey(request), recent);
      return fail(request, response, 429, "rate_limited", "Too many requests. Try again in 600 seconds.", { retryAfterSeconds: 600 });
    }
    registrations.set(clientKey(request), [...recent, now]);
    let code;
    do code = Array.from(randomBytes(16), (byte) => String(byte % 10)).join("");
    while (accounts.has(code));
    const account = {
      id: `acc_${randomBytes(4).toString("hex")}`,
      paidUntil: new Date(Math.ceil((now + 7 * DAY) / 3_600_000) * 3_600_000).toISOString(),
      settings: defaultSettings(),
      devices: [],
    };
    accounts.set(code, account);
    const token = randomBytes(32).toString("base64url");
    sessions.set(token, code);
    return send(request, response, 200, { code, token, account: { id: account.id, paidUntil: account.paidUntil } });
  }

  if (request.method === "GET" && path === "/__mock/latency") {
    return send(request, response, 200, Object.fromEntries(nodes.filter((node) => node.latencyMs !== undefined).map((node) => [node.id, node.latencyMs])));
  }

  if (request.method === "GET" && path === "/api/v1/nodes") {
    return send(request, response, 200, nodes.map(publicNode));
  }

  const auth = authenticate(request);
  if (!auth) return fail(request, response, 401, "unauthorized", "Not signed in or the session has expired.");
  const { account } = auth;

  if (
    handleTickets({
      method: request.method,
      path,
      url,
      body,
      account,
      send: (status, payload) => send(request, response, status, payload),
      fail: (status, code, error, params) => fail(request, response, status, code, error, params),
    })
  ) {
    return;
  }

  if (request.method === "POST" && path === "/api/v1/auth/logout") {
    sessions.delete(auth.token);
    return send(request, response, 204);
  }

  if (request.method === "GET" && path === "/api/v1/account") {
    return send(request, response, 200, publicAccount(account));
  }

  if (request.method === "PATCH" && path === "/api/v1/settings") {
    const patch = parsePatch(body);
    if (!patch) return fail(request, response, 400, "validation_failed", "The request is invalid.");
    account.settings = { ...account.settings, ...patch, dns: { ...account.settings.dns, ...(patch.dns ?? {}) } };
    return send(request, response, 200, account.settings);
  }

  if (request.method === "POST" && path === "/api/v1/devices") {
    if (Date.parse(account.paidUntil) < Date.now()) {
      return fail(request, response, 403, "account_expired", "The account has expired. Redeem a voucher before adding devices.");
    }
    if (!isRecord(body)) return fail(request, response, 400, "body_not_object", "The request body must be a JSON object.");
    const { name, nodeId, publicKey } = body;
    if (typeof name !== "string" || name.length < 1 || name.length > 64) {
      return fail(request, response, 400, "invalid_device_name", "name must be a string.");
    }
    const node = nodes.find((entry) => entry.id === nodeId);
    if (!node) return fail(request, response, 404, "unknown_location", "Unknown location.");
    if (node.status === "paused") {
      return fail(request, response, 503, "location_paused", "This location is not accepting new devices right now.");
    }
    if (node.status === "upgrading") {
      return fail(request, response, 503, "location_upgrading", `${node.city} is being migrated to a new system and does not accept new devices. Choose another location.`, {
        city: node.city,
      });
    }
    if (node.status === "full") {
      return fail(request, response, 503, "location_full", `${node.city} has no free addresses left. Choose another location.`, { city: node.city });
    }
    if (!node.online) {
      return fail(request, response, 503, "node_unavailable", `${node.city} is unreachable right now. Try again shortly or choose another location.`, {
        city: node.city,
      });
    }
    if (publicKey !== undefined && !isWgKey(publicKey)) {
      return fail(request, response, 400, "invalid_public_key", "publicKey is not a valid WireGuard public key.");
    }
    if (account.devices.length >= DEVICE_LIMIT) {
      return fail(request, response, 409, "device_limit_reached", `An account can have at most ${DEVICE_LIMIT} devices. Remove one first.`, {
        max: DEVICE_LIMIT,
      });
    }
    const generated =
      node.id === "local-pq"
        ? { privateKey: localPq.clientPrivateKey, publicKey: localPq.clientPublicKey }
        : SERVER_GENERATES_KEYS || publicKey === undefined
          ? wgKeyPair()
          : null;
    const devicePublicKey = generated ? generated.publicKey : publicKey;
    if (account.devices.some((device) => device.publicKey === devicePublicKey)) {
      return fail(request, response, 409, "public_key_taken", "This public key is already registered for a device. Generate a new key pair.");
    }
    if (node.id === "local-pq") {
      for (const other of accounts.values()) other.devices = other.devices.filter((entry) => entry.nodeId !== "local-pq");
    }
    hostCounter += 1;
    const ipv4 = `10.64.${Math.floor(hostCounter / 250)}.${(hostCounter % 250) + 2}`;
    const ipv6 = `fd00:6d61:6e74::${hostCounter.toString(16)}`;
    const device = {
      id: `dev_${randomUUID().replace(/-/g, "").slice(0, 12)}`,
      name,
      nodeId: node.id,
      ipv4: node.id === "local-pq" ? localPq.tunnelIpv4 : ipv4,
      ipv6: node.id === "local-pq" ? null : ipv6,
      createdOn: new Date().toISOString(),
      publicKey: devicePublicKey,
      obfsToken: randomBytes(32).toString("hex"),
    };
    account.devices.push(device);
    const { publicKey: _omit, ...publicDevice } = device;
    const local = node.id === "local-pq";
    const config = local
      ? { address: [`${localPq.tunnelIpv4}/32`], dns: [localPq.nodeIpv4], serverPublicKey: node.serverPublicKey, endpoint: localPq.endpoint, allowedIps: ["0.0.0.0/0"] }
      : {
      address: [`${ipv4}/32`, `${ipv6}/128`],
      dns: ["10.64.0.1", "fd00:6d61:6e74::1"],
      serverPublicKey: node.serverPublicKey,
      presharedKey: randomBytes(32).toString("base64"),
      endpoint: node.endpointHost.includes(":") ? `[${node.endpointHost}]:${node.endpointPort}` : `${node.endpointHost}:${node.endpointPort}`,
      allowedIps: ["0.0.0.0/0", "::/0"],
      mtu: 1420,
    };
    return send(request, response, 201, { device: publicDevice, config, ...(generated ? { privateKey: generated.privateKey } : {}) });
  }

  const forwardMatch = path.match(/^\/api\/v1\/devices\/([A-Za-z0-9_-]{1,64})\/port-forwarding(?:\/(\d{1,5}))?$/);
  if (forwardMatch) {
    const device = account.devices.find((entry) => entry.id === forwardMatch[1]);
    if (!device) return fail(request, response, 404, "device_not_found", "Device not found.");
    device.forwardPorts ??= [];
    const node = nodes.find((entry) => entry.id === device.nodeId);
    const expired = Date.parse(account.paidUntil) <= Date.now();
    const reason = expired ? "expired" : !node?.online ? "offline" : node.portForwarding ? null : "unsupported";
    const view = () => ({
      deviceId: device.id,
      nodeId: device.nodeId,
      city: node?.city ?? device.nodeId,
      country: node?.country ?? "DE",
      available: reason === null,
      reason,
      max: FORWARD_MAX,
      forwards: device.forwardPorts.map((port) => ({ port, host: node?.endpointHost ?? "198.51.100.1", protocols: ["tcp", "udp"] })),
    });
    const single = forwardMatch[2] === undefined ? null : Number(forwardMatch[2]);
    if (request.method === "GET" && single === null) return send(request, response, 200, view());
    if (request.method === "POST" && single === null) {
      if (expired) return fail(request, response, 403, "account_expired", "The account has expired. Redeem a voucher before adding devices.");
      if (reason) return fail(request, response, 503, "port_forwarding_unavailable", `${node?.city ?? "This location"} does not offer port forwarding right now.`, { city: node?.city ?? "" });
      if (device.forwardPorts.length >= FORWARD_MAX) {
        return fail(request, response, 409, "port_forward_limit_reached", `At most ${FORWARD_MAX} forwarded ports are allowed. Remove one first.`, { max: FORWARD_MAX });
      }
      device.forwardPorts.push(20000 + Math.floor(Math.random() * 30000));
      return send(request, response, 201, view());
    }
    if (request.method === "DELETE") {
      if (single !== null && !device.forwardPorts.includes(single)) return fail(request, response, 404, "port_forward_not_found", "This forwarded port does not exist.");
      device.forwardPorts = single === null ? [] : device.forwardPorts.filter((port) => port !== single);
      return send(request, response, 200, view());
    }
    return fail(request, response, 405, "method_not_allowed", "This method is not allowed for this endpoint.");
  }

  const proxyMatch = path.match(/^\/api\/v1\/proxies(?:\/([A-Za-z0-9_-]{1,64}))?$/);
  if (proxyMatch && PROXIES_OFFERED) {
    account.proxies ??= [];
    const id = proxyMatch[1];
    const newPassword = () => randomBytes(15).toString("base64url");
    const withTelegram = (proxy) => {
      const secret = `ee${randomBytes(16).toString("hex")}${Buffer.from("www.cloudflare.com").toString("hex")}`;
      const query = `server=${encodeURIComponent(proxy.host)}&port=${proxy.port}&secret=${secret}`;
      return Object.assign(proxy, { username: "", secret, link: `tg://proxy?${query}`, webLink: `https://t.me/proxy?${query}` });
    };
    if (!id && request.method === "GET") return send(request, response, 200, { proxies: account.proxies });
    if (!id && request.method === "POST") {
      const node = nodes.find((entry) => entry.id === body?.nodeId && entry.online);
      if (!node) return fail(request, response, 400, "unknown_location", "Unknown location.");
      if (account.proxies.length >= 20) return fail(request, response, 409, "proxy_limit_reached", "At most 20 proxies.", { max: 20 });
      const proxy = {
        id: `px_${randomUUID().replace(/-/g, "").slice(0, 10)}`,
        name: String(body?.name ?? "Proxy").slice(0, 40),
        nodeId: node.id,
        host: node.endpointHost,
        port: 30000 + Math.floor(Math.random() * 20000),
        protocol: body?.protocol === "http" || body?.protocol === "mtproto" ? body.protocol : "socks5",
        exit: body?.exit === "tor" ? "tor" : "direct",
        username: `m-${randomBytes(4).toString("hex")}`,
        enabled: true,
        status: "pending",
      };
      if (proxy.protocol === "mtproto") withTelegram(proxy);
      account.proxies.push(proxy);
      setTimeout(() => (proxy.status = "active"), 3000);
      return send(request, response, 201, { proxy, password: proxy.secret ?? newPassword() });
    }
    const proxy = id ? account.proxies.find((entry) => entry.id === id) : undefined;
    if (!proxy) return fail(request, response, 404, "proxy_not_found", "Proxy not found.");
    if (request.method === "PATCH") {
      if (typeof body?.name === "string") proxy.name = body.name.slice(0, 40);
      if (typeof body?.enabled === "boolean") proxy.enabled = body.enabled;
      if (body?.exit === "tor" || body?.exit === "direct") proxy.exit = body.exit;
      if (body?.rotatePassword === true && proxy.protocol === "mtproto") return send(request, response, 200, { proxy: withTelegram(proxy), password: proxy.secret });
      return send(request, response, 200, { proxy, ...(body?.rotatePassword === true ? { password: newPassword() } : {}) });
    }
    if (request.method === "DELETE") {
      account.proxies = account.proxies.filter((entry) => entry !== proxy);
      return send(request, response, 204);
    }
    return fail(request, response, 405, "method_not_allowed", "This method is not allowed for this endpoint.");
  }

  const deviceMatch = path.match(/^\/api\/v1\/devices\/([A-Za-z0-9_-]{1,64})$/);
  if (request.method === "PATCH" && deviceMatch) {
    const device = account.devices.find((entry) => entry.id === deviceMatch[1]);
    if (!device) return fail(request, response, 404, "device_not_found", "Device not found.");
    if (typeof body?.name !== "string" || !body.name.trim()) return fail(request, response, 400, "invalid_device_name", "name must be a string.");
    if (body.name.trim().length > 32) return fail(request, response, 400, "device_name_too_long", "Device names can have at most 32 characters.", { max: 32 });
    device.name = body.name.trim().replace(/\s+/g, " ");
    const { publicKey: _omit, forwardPorts: _ports, ...publicDevice } = device;
    return send(request, response, 200, publicDevice);
  }
  if (request.method === "DELETE" && deviceMatch) {
    const index = account.devices.findIndex((device) => device.id === deviceMatch[1]);
    if (index === -1) return fail(request, response, 404, "device_not_found", "Device not found.");
    account.devices.splice(index, 1);
    return send(request, response, 204);
  }

  return fail(request, response, 404, "not_found", "Not found.");
}

const server = createServer((request, response) => {
  route(request, response).catch(() => fail(request, response, 500, "internal", "Internal server error. Please try again shortly."));
});

server.listen(PORT, HOST, () => {
  process.stdout.write(
    `Mantel Mock-API auf http://${HOST}:${PORT}\n` +
      "  Konto (aktiv):     1234 5678 9012 3456\n" +
      "  Konto (abgelaufen): 1111 2222 3333 4444\n" +
      `  Server-Schlüssel:  ${SERVER_GENERATES_KEYS ? "Server erzeugt privateKey (Fallback)" : "Client-Schlüssel"}\n`,
  );
});
