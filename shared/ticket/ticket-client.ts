import {
  cleanMessage,
  decryptText,
  encryptText,
  exportPrivateKey,
  fromBase64Url,
  generateKeyPair,
  importPrivateKey,
  publicKeyId,
  publicKeyOf,
  randomContentKey,
  randomTicketId,
  titleFrom,
  unwrapSecret,
  wrapContext,
  wrapSecret,
  type TicketKey,
} from "./ticket-crypto";

export const TICKET_CATEGORIES = ["connection", "account", "payment", "app", "other"] as const;
export type TicketCategory = (typeof TICKET_CATEGORIES)[number];
export type TicketStatus = "open" | "waiting" | "closed";

export type TicketTransport = (request: {
  method: "GET" | "POST" | "DELETE";
  path: string;
  query?: Record<string, string>;
  body?: unknown;
  headers?: Record<string, string>;
}) => Promise<{ status: number; body: unknown }>;

export class TicketApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly body: unknown = null,
  ) {
    super(message);
    this.name = "TicketApiError";
  }
}

type Obj = Record<string, unknown>;

async function send<T = Obj>(transport: TicketTransport, request: Parameters<TicketTransport>[0]): Promise<T> {
  const response = await transport(request);
  if (response.status >= 200 && response.status < 300) return (response.body ?? {}) as T;
  const body = (response.body ?? {}) as Obj;
  const code = typeof body.code === "string" ? body.code : `http_${response.status}`;
  const message = typeof body.error === "string" ? body.error : `HTTP ${response.status}`;
  throw new TicketApiError(response.status, code, message, response.body);
}

export type DeviceKey = { keyId: string; publicKey: string; privateKey: TicketKey };

export type TicketSummary = {
  id: string;
  number: number;
  category: TicketCategory;
  status: TicketStatus;
  title: string | null;
  readable: boolean;
  unread: number;
  createdAt: number;
  updatedAt: number;
  closedAt: number | null;
  lastActor: "user" | "team";
  messageCount: number;
};

export type TicketMessage = {
  seq: number;
  role: "user" | "team";
  text: string | null;
  createdAt: number;
  author?: string | null;
};

export type TicketThread = TicketSummary & { messages: TicketMessage[] };

type RawSummary = {
  id: string;
  number: number;
  category: TicketCategory;
  status: TicketStatus;
  title: string;
  createdAt: number;
  updatedAt: number;
  closedAt: number | null;
  lastActor: "user" | "team";
  messageCount: number;
  unread: number;
  wrapped: string | null;
};

type RawMessage = { seq: number; role: "user" | "team" | "note"; ciphertext: string; createdAt: number; author?: string | null };

export async function newDeviceKey(extractable: boolean): Promise<DeviceKey & { pkcs8: string | null }> {
  const pair = await generateKeyPair(extractable);
  return { ...pair, pkcs8: extractable ? await exportPrivateKey(pair.privateKey) : null };
}

export async function deviceKeyFromPkcs8(pkcs8: string): Promise<DeviceKey> {
  const extractable = await importPrivateKey(pkcs8, true);
  const publicKey = await publicKeyOf(extractable);
  return { keyId: await publicKeyId(publicKey), publicKey, privateKey: await importPrivateKey(pkcs8, false) };
}

export type UserPlatform = "windows" | "macos" | "android" | "web" | "linux";

export async function registerDeviceKey(transport: TicketTransport, key: DeviceKey, platform: UserPlatform): Promise<void> {
  await send(transport, { method: "POST", path: "keys", body: { publicKey: key.publicKey, platform } });
}

export async function unregisterDeviceKey(transport: TicketTransport, keyId: string): Promise<void> {
  try {
    await send(transport, { method: "DELETE", path: `keys/${keyId}` });
  } catch (error) {
    if (!(error instanceof TicketApiError && (error.status === 404 || error.status === 401))) throw error;
  }
}

async function contentKeyFor(device: DeviceKey, ticketId: string, wrapped: string | null): Promise<Uint8Array | null> {
  if (!wrapped) return null;
  try {
    return await unwrapSecret(wrapped, device.privateKey, device.publicKey, wrapContext.content(ticketId));
  } catch {
    return null;
  }
}

async function decryptOr(key: Uint8Array | null, ciphertext: string, position: Parameters<typeof decryptText>[2]): Promise<string | null> {
  if (!key) return null;
  try {
    return await decryptText(key, ciphertext, position);
  } catch {
    return null;
  }
}

async function summarize(raw: RawSummary, key: Uint8Array | null): Promise<TicketSummary> {
  const title = await decryptOr(key, raw.title, { ticketId: raw.id, kind: "title", seq: 0, role: "user" });
  return {
    id: raw.id,
    number: raw.number,
    category: raw.category,
    status: raw.status,
    title,
    readable: key !== null,
    unread: raw.unread,
    createdAt: raw.createdAt,
    updatedAt: raw.updatedAt,
    closedAt: raw.closedAt,
    lastActor: raw.lastActor,
    messageCount: raw.messageCount,
  };
}

export type UserTicketList = { available: boolean; unread: number; tickets: TicketSummary[] };

export async function listTickets(transport: TicketTransport, device: DeviceKey): Promise<UserTicketList> {
  const body = await send<{ available: boolean; unread: number; tickets: RawSummary[] }>(transport, { method: "GET", path: "", query: { key: device.keyId } });
  const tickets = await Promise.all(body.tickets.map(async (raw) => summarize(raw, await contentKeyFor(device, raw.id, raw.wrapped))));
  return { available: body.available, unread: body.unread, tickets };
}

export async function unreadCount(transport: TicketTransport): Promise<{ available: boolean; unread: number }> {
  const body = await send<{ available: boolean; unread: number }>(transport, { method: "GET", path: "" });
  return { available: body.available, unread: body.unread };
}

async function decryptMessages(key: Uint8Array | null, ticketId: string, raw: RawMessage[]): Promise<TicketMessage[]> {
  return Promise.all(
    raw.map(async (message) => ({
      seq: message.seq,
      role: message.role === "team" ? ("team" as const) : ("user" as const),
      text: await decryptOr(key, message.ciphertext, { ticketId, kind: "msg", seq: message.seq, role: message.role }),
      createdAt: message.createdAt,
      ...(message.author !== undefined ? { author: message.author } : {}),
    })),
  );
}

export async function openTicket(transport: TicketTransport, device: DeviceKey, id: string): Promise<TicketThread> {
  const raw = await send<RawSummary & { messages: RawMessage[] }>(transport, { method: "GET", path: id, query: { key: device.keyId } });
  const key = await contentKeyFor(device, id, raw.wrapped);
  return { ...(await summarize(raw, key)), messages: await decryptMessages(key, id, raw.messages) };
}

export class TicketInputError extends Error {
  constructor(readonly reason: "empty" | "too_long" | "no_key" | "unavailable") {
    super(reason);
    this.name = "TicketInputError";
  }
}

export async function createTicket(
  transport: TicketTransport,
  device: DeviceKey,
  category: TicketCategory,
  input: string,
): Promise<{ id: string; number: number }> {
  const text = cleanMessage(input);
  if (!text) throw new TicketInputError(input.trim() ? "too_long" : "empty");
  const keys = await send<{ team: { version: number; publicKey: string } | null; devices: { keyId: string; publicKey: string }[] }>(transport, {
    method: "GET",
    path: "keys",
  });
  if (!keys.team) throw new TicketInputError("unavailable");
  const id = randomTicketId();
  const contentKey = randomContentKey();
  const context = wrapContext.content(id);
  const recipients = new Map<string, string>([[`user:${device.keyId}`, device.publicKey]]);
  for (const own of keys.devices) recipients.set(`user:${own.keyId}`, own.publicKey);
  const wraps = [{ recipient: `team:${keys.team.version}`, wrapped: await wrapSecret(contentKey, keys.team.publicKey, context) }];
  for (const [recipient, publicKey] of recipients) wraps.push({ recipient, wrapped: await wrapSecret(contentKey, publicKey, context) });
  const body = {
    id,
    category,
    key: device.keyId,
    keys: wraps.slice(0, 16),
    title: await encryptText(contentKey, titleFrom(text), { ticketId: id, kind: "title", seq: 0, role: "user" }),
    message: await encryptText(contentKey, text, { ticketId: id, kind: "msg", seq: 1, role: "user" }),
  };
  const created = await send<{ id: string; number: number }>(transport, { method: "POST", path: "", body });
  return { id: created.id, number: created.number };
}

async function appendWithRetry(
  transport: TicketTransport,
  path: string,
  load: () => Promise<{ count: number; key: Uint8Array | null }>,
  encrypt: (key: Uint8Array, seq: number) => Promise<string>,
): Promise<number> {
  for (let attempt = 0; ; attempt += 1) {
    const { count, key } = await load();
    if (!key) throw new TicketInputError("no_key");
    const seq = count + 1;
    try {
      await send(transport, { method: "POST", path, body: { seq, ciphertext: await encrypt(key, seq) } });
      return seq;
    } catch (error) {
      if (!(error instanceof TicketApiError && error.code === "ticket_changed") || attempt >= 2) throw error;
    }
  }
}

export async function replyToTicket(transport: TicketTransport, device: DeviceKey, id: string, input: string): Promise<number> {
  const text = cleanMessage(input);
  if (!text) throw new TicketInputError(input.trim() ? "too_long" : "empty");
  return appendWithRetry(
    transport,
    `${id}/messages`,
    async () => {
      const raw = await send<RawSummary>(transport, { method: "GET", path: id, query: { key: device.keyId } });
      return { count: raw.messageCount, key: await contentKeyFor(device, id, raw.wrapped) };
    },
    (key, seq) => encryptText(key, text, { ticketId: id, kind: "msg", seq, role: "user" }),
  );
}

export async function setTicketClosed(transport: TicketTransport, id: string, closed: boolean): Promise<TicketStatus> {
  const body = await send<{ status: TicketStatus }>(transport, { method: "POST", path: `${id}/${closed ? "close" : "reopen"}` });
  return body.status;
}

export async function markSeen(transport: TicketTransport, id: string, seq: number): Promise<void> {
  await send(transport, { method: "POST", path: `${id}/seen`, body: { seq } });
}

export async function rewrapForOwnDevices(transport: TicketTransport, device: DeviceKey): Promise<number> {
  const work = await send<{ items: { ticketId: string; wrapped: string; missing: { keyId: string; publicKey: string }[] }[] }>(transport, {
    method: "GET",
    path: "rewrap",
    query: { key: device.keyId },
  });
  if (work.items.length === 0) return 0;
  const items: { ticketId: string; keyId: string; wrapped: string }[] = [];
  for (const item of work.items) {
    const key = await contentKeyFor(device, item.ticketId, item.wrapped);
    if (!key) continue;
    for (const other of item.missing) {
      items.push({ ticketId: item.ticketId, keyId: other.keyId, wrapped: await wrapSecret(key, other.publicKey, wrapContext.content(item.ticketId)) });
    }
  }
  if (items.length === 0) return 0;
  const stored = await send<{ stored: number }>(transport, { method: "POST", path: "rewrap", body: { items } });
  return stored.stored;
}

export type TeamVersion = { version: number; publicKey: string; keyId: string; state?: string };

export type TeamDevice = { keyId: string; publicKey: string; label: string; kind: "web" | "app"; admin: string; createdAt: number; active: boolean };

export type TeamState = {
  current: TeamVersion | null;
  versions: TeamVersion[];
  device: { keyId: string | null; status: "none" | "pending" | "active" | "revoked" };
  grants: { version: number; wrapped: string }[];
  devices: TeamDevice[];
  rotationNeeded: boolean;
  rewrapPending: number;
  canBootstrap: boolean;
};

export type TeamRing = Map<number, { privateKey: TicketKey; publicKey: string; pkcs8: Uint8Array }>;

export async function teamState(transport: TicketTransport, keyId: string | null): Promise<TeamState> {
  return send<TeamState>(transport, { method: "GET", path: "team", query: keyId ? { key: keyId } : {} });
}

export async function registerAdminDevice(transport: TicketTransport, key: DeviceKey, label: string): Promise<void> {
  await send(transport, { method: "POST", path: "team/devices", body: { publicKey: key.publicKey, label } });
}

export class TeamKeyMismatch extends Error {
  constructor(readonly version: number) {
    super(`Team-Schlüssel Version ${version} stimmt nicht mit dem veröffentlichten Schlüssel überein.`);
    this.name = "TeamKeyMismatch";
  }
}

export async function ringFromGrants(device: DeviceKey, state: TeamState): Promise<TeamRing> {
  const ring: TeamRing = new Map();
  for (const grant of state.grants) {
    const pkcs8 = await unwrapSecret(grant.wrapped, device.privateKey, device.publicKey, wrapContext.team(grant.version));
    await addToRing(ring, grant.version, pkcs8);
  }
  checkRing(ring, state);
  return ring;
}

export async function addToRing(ring: TeamRing, version: number, pkcs8: Uint8Array | string): Promise<void> {
  const bytes = typeof pkcs8 === "string" ? fromBase64Url(pkcs8) : pkcs8;
  if (!bytes) throw new Error("Ungültiger Team-Schlüssel.");
  const extractable = await importPrivateKey(bytes, true);
  ring.set(version, { privateKey: await importPrivateKey(bytes, false), publicKey: await publicKeyOf(extractable), pkcs8: bytes });
}

export function checkRing(ring: TeamRing, state: TeamState): void {
  for (const version of state.versions) {
    const held = ring.get(version.version);
    if (held && held.publicKey !== version.publicKey) throw new TeamKeyMismatch(version.version);
  }
}

export function pruneRing(ring: TeamRing, state: TeamState): void {
  const live = new Set(state.versions.map((version) => version.version));
  for (const version of [...ring.keys()]) if (!live.has(version)) ring.delete(version);
}

export async function bootstrapTeam(transport: TicketTransport, device: DeviceKey, headers: Record<string, string> = {}): Promise<TeamRing> {
  const team = await generateKeyPair(true);
  const pkcs8 = fromBase64Url(await exportPrivateKey(team.privateKey))!;
  const grant = await wrapSecret(pkcs8, device.publicKey, wrapContext.team(1));
  await send(transport, { method: "POST", path: "team/bootstrap", body: { key: device.keyId, publicKey: team.publicKey, grant }, headers });
  const ring: TeamRing = new Map();
  await addToRing(ring, 1, pkcs8);
  return ring;
}

export async function grantTeamKey(
  transport: TicketTransport,
  device: DeviceKey,
  ring: TeamRing,
  state: TeamState,
  target: Pick<TeamDevice, "keyId" | "publicKey">,
  headers: Record<string, string> = {},
): Promise<void> {
  const grants = [];
  for (const version of state.versions) {
    const held = ring.get(version.version);
    if (!held) throw new Error(`Version ${version.version} fehlt auf diesem Gerät.`);
    grants.push({ version: version.version, wrapped: await wrapSecret(held.pkcs8, target.publicKey, wrapContext.team(version.version)) });
  }
  await send(transport, { method: "POST", path: "team/grant", body: { key: device.keyId, target: target.keyId, grants }, headers });
}

export async function removeAdminDevice(transport: TicketTransport, keyId: string, headers: Record<string, string> = {}): Promise<void> {
  await send(transport, { method: "DELETE", path: `team/devices/${keyId}`, headers });
}

export async function rotateTeam(transport: TicketTransport, device: DeviceKey, ring: TeamRing, state: TeamState): Promise<number> {
  if (!state.current) throw new Error("Kein Team-Schlüssel.");
  const version = state.current.version + 1;
  const team = await generateKeyPair(true);
  const pkcs8 = fromBase64Url(await exportPrivateKey(team.privateKey))!;
  const holders = state.devices.filter((entry) => entry.active);
  if (!holders.some((entry) => entry.keyId === device.keyId)) holders.push({ keyId: device.keyId, publicKey: device.publicKey } as TeamDevice);
  const grants = [];
  for (const holder of holders) grants.push({ keyId: holder.keyId, wrapped: await wrapSecret(pkcs8, holder.publicKey, wrapContext.team(version)) });
  await send(transport, { method: "POST", path: "team/rotate", body: { key: device.keyId, fromVersion: state.current.version, publicKey: team.publicKey, grants } });
  await addToRing(ring, version, pkcs8);
  return version;
}

export async function rewrapTeamStep(transport: TicketTransport, device: DeviceKey, ring: TeamRing): Promise<number> {
  const work = await send<{ version: number | null; items: { ticketId: string; purpose: "content" | "note"; version: number; wrapped: string }[] }>(transport, {
    method: "GET",
    path: "team/rewrap",
    query: { key: device.keyId },
  });
  if (work.version === null || work.items.length === 0) return 0;
  const current = ring.get(work.version);
  if (!current) return work.items.length;
  const items = [];
  for (const item of work.items) {
    const old = ring.get(item.version);
    if (!old) continue;
    const context = item.purpose === "content" ? wrapContext.content(item.ticketId) : wrapContext.note(item.ticketId);
    try {
      const secret = await unwrapSecret(item.wrapped, old.privateKey, old.publicKey, context);
      items.push({ ticketId: item.ticketId, purpose: item.purpose, wrapped: await wrapSecret(secret, current.publicKey, context) });
    } catch {
    }
  }
  if (items.length === 0) return 0;
  const result = await send<{ remaining: number }>(transport, { method: "POST", path: "team/rewrap", body: { key: device.keyId, version: work.version, items } });
  return result.remaining;
}

export async function teamMaintenance(transport: TicketTransport, device: DeviceKey, ring: TeamRing, state: TeamState, rounds = 5): Promise<boolean> {
  let changed = false;
  if (state.rotationNeeded && state.device.status === "active") {
    try {
      await rotateTeam(transport, device, ring, state);
      changed = true;
    } catch {
      return changed;
    }
  }
  for (let round = 0; round < rounds; round += 1) {
    try {
      const remaining = await rewrapTeamStep(transport, device, ring);
      if (remaining === 0) break;
      changed = true;
    } catch {
      break;
    }
  }
  return changed;
}

function teamKeyOf(ring: TeamRing, wraps: Record<string, string>, ticketId: string, purpose: "content" | "note"): Promise<Uint8Array | null> {
  const entries = Object.entries(wraps).sort((a, b) => Number(b[0]) - Number(a[0]));
  return (async () => {
    for (const [version, wrapped] of entries) {
      const held = ring.get(Number(version));
      if (!held) continue;
      try {
        return await unwrapSecret(wrapped, held.privateKey, held.publicKey, purpose === "content" ? wrapContext.content(ticketId) : wrapContext.note(ticketId));
      } catch {
      }
    }
    return null;
  })();
}

export type AdminTicketSummary = TicketSummary & { account: string; assignee: string | null; noteCount: number };
export type AdminNote = { seq: number; text: string | null; createdAt: number; author: string | null };
export type AdminThread = AdminTicketSummary & { messages: TicketMessage[]; notes: AdminNote[]; blocked: string | null };

type RawAdminSummary = Omit<RawSummary, "wrapped"> & { account: string; assignee: string | null; noteCount: number; wraps: Record<string, string> };

export type AdminFilter = { status?: "open" | "waiting" | "closed" | "all" | "active"; category?: TicketCategory | ""; assignee?: "me" | ""; before?: number };

export async function adminListTickets(
  transport: TicketTransport,
  ring: TeamRing,
  filter: AdminFilter = {},
): Promise<{ tickets: AdminTicketSummary[]; counts: Record<string, number>; unread: number }> {
  const query: Record<string, string> = {};
  if (filter.status && filter.status !== "active") query.status = filter.status;
  if (filter.category) query.category = filter.category;
  if (filter.assignee) query.assignee = filter.assignee;
  if (filter.before) query.before = String(filter.before);
  const body = await send<{ tickets: RawAdminSummary[]; counts: Record<string, number>; unread: number }>(transport, { method: "GET", path: "", query });
  const tickets = await Promise.all(
    body.tickets.map(async (raw) => {
      const key = await teamKeyOf(ring, raw.wraps, raw.id, "content");
      return { ...(await summarize({ ...raw, wrapped: null }, key)), account: raw.account, assignee: raw.assignee, noteCount: raw.noteCount };
    }),
  );
  return { tickets, counts: body.counts, unread: body.unread };
}

export async function adminOpenTicket(transport: TicketTransport, ring: TeamRing, id: string): Promise<AdminThread> {
  const raw = await send<RawAdminSummary & { noteWraps: Record<string, string>; messages: RawMessage[]; notes: RawMessage[]; blocked?: string | null }>(transport, {
    method: "GET",
    path: id,
  });
  const key = await teamKeyOf(ring, raw.wraps, id, "content");
  const noteKey = await teamKeyOf(ring, raw.noteWraps, id, "note");
  const notes = await Promise.all(
    raw.notes.map(async (note) => ({
      seq: note.seq,
      text: await decryptOr(noteKey, note.ciphertext, { ticketId: id, kind: "note", seq: note.seq, role: "note" }),
      createdAt: note.createdAt,
      author: note.author ?? null,
    })),
  );
  return {
    ...(await summarize({ ...raw, wrapped: null }, key)),
    account: raw.account,
    assignee: raw.assignee,
    noteCount: raw.noteCount,
    messages: await decryptMessages(key, id, raw.messages),
    notes,
    blocked: typeof raw.blocked === "string" ? raw.blocked : null,
  };
}

export async function adminReply(transport: TicketTransport, ring: TeamRing, id: string, input: string): Promise<number> {
  const text = cleanMessage(input);
  if (!text) throw new TicketInputError(input.trim() ? "too_long" : "empty");
  return appendWithRetry(
    transport,
    `${id}/messages`,
    async () => {
      const raw = await send<RawAdminSummary>(transport, { method: "GET", path: id });
      return { count: raw.messageCount, key: await teamKeyOf(ring, raw.wraps, id, "content") };
    },
    (key, seq) => encryptText(key, text, { ticketId: id, kind: "msg", seq, role: "team" }),
  );
}

export async function adminNote(transport: TicketTransport, ring: TeamRing, state: TeamState, id: string, input: string): Promise<number> {
  const text = cleanMessage(input);
  if (!text) throw new TicketInputError(input.trim() ? "too_long" : "empty");
  for (let attempt = 0; ; attempt += 1) {
    const raw = await send<RawAdminSummary & { noteWraps: Record<string, string> }>(transport, { method: "GET", path: id });
    let noteKey = await teamKeyOf(ring, raw.noteWraps, id, "note");
    let wrappedNew: string | undefined;
    if (Object.keys(raw.noteWraps).length === 0) {
      const current = state.current ? ring.get(state.current.version) : undefined;
      if (!current || !state.current) throw new TicketInputError("no_key");
      noteKey = randomContentKey();
      wrappedNew = await wrapSecret(noteKey, state.current.publicKey, wrapContext.note(id));
    }
    if (!noteKey) throw new TicketInputError("no_key");
    const seq = raw.noteCount + 1;
    try {
      await send(transport, {
        method: "POST",
        path: `${id}/notes`,
        body: { seq, ciphertext: await encryptText(noteKey, text, { ticketId: id, kind: "note", seq, role: "note" }), ...(wrappedNew ? { noteKey: wrappedNew } : {}) },
      });
      return seq;
    } catch (error) {
      if (!(error instanceof TicketApiError && (error.code === "ticket_changed" || error.code === "conflict")) || attempt >= 2) throw error;
    }
  }
}

export async function adminSetStatus(transport: TicketTransport, id: string, status: "open" | "closed"): Promise<TicketStatus> {
  return (await send<{ status: TicketStatus }>(transport, { method: "POST", path: `${id}/status`, body: { status } })).status;
}

export async function adminAssign(transport: TicketTransport, id: string, mine: boolean): Promise<void> {
  await send(transport, { method: "POST", path: `${id}/assign`, body: { assignee: mine ? "me" : null } });
}

export async function adminSetBlocked(transport: TicketTransport, id: string, blocked: boolean, reason = ""): Promise<string | null> {
  return (await send<{ blocked: string | null }>(transport, { method: "POST", path: `${id}/block`, body: blocked ? { blocked, reason } : { blocked } })).blocked;
}

export async function adminSeen(transport: TicketTransport, id: string, seq: number): Promise<void> {
  await send(transport, { method: "POST", path: `${id}/seen`, body: { seq } });
}
