export type PeerStatus = {
  publicKey: string;
  endpoint: string | null;
  latestHandshakeAt: number | null;
  rxBytes: number;
  txBytes: number;
};

export type InterfaceStatus = {
  publicKey: string;
  peers: PeerStatus[];
};

export type ServiceState =
  | "STOPPED"
  | "START_PENDING"
  | "STOP_PENDING"
  | "RUNNING"
  | "CONTINUE_PENDING"
  | "PAUSE_PENDING"
  | "PAUSED";

const SERVICE_STATES: readonly ServiceState[] = [
  "STOPPED",
  "START_PENDING",
  "STOP_PENDING",
  "RUNNING",
  "CONTINUE_PENDING",
  "PAUSE_PENDING",
  "PAUSED",
];

function toNumber(value: string | undefined): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

const WG_KEY = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;

function peerColumns(output: string, columns: number): Map<string, string[]> {
  const rows = new Map<string, string[]>();
  for (const line of output.split(/\r?\n/)) {
    const fields = line.trim().split("\t");
    const key = fields[0] ?? "";
    if (fields.length === columns + 1 && WG_KEY.test(key)) rows.set(key, fields.slice(1));
  }
  return rows;
}

export function parseWgShow(output: { publicKey: string; latestHandshakes: string; transfer: string; endpoints: string }): InterfaceStatus | null {
  const publicKey = output.publicKey.trim();
  if (!WG_KEY.test(publicKey)) return null;
  const transfer = peerColumns(output.transfer, 2);
  const endpoints = peerColumns(output.endpoints, 1);
  const peers = [...peerColumns(output.latestHandshakes, 1)].map(([key, [seconds]]): PeerStatus => {
    const handshake = toNumber(seconds);
    const [rx, tx] = transfer.get(key) ?? [];
    const endpoint = endpoints.get(key)?.[0];
    return {
      publicKey: key,
      endpoint: endpoint && endpoint !== "(none)" ? endpoint : null,
      latestHandshakeAt: handshake > 0 ? handshake * 1000 : null,
      rxBytes: toNumber(rx),
      txBytes: toNumber(tx),
    };
  });
  return { publicKey, peers };
}

export function parseScQuery(output: string): ServiceState | null {
  const match = output.match(/:\s*[1-7]\s+(STOPPED|START_PENDING|STOP_PENDING|RUNNING|CONTINUE_PENDING|PAUSE_PENDING|PAUSED)\b/);
  const state = match?.[1];
  return SERVICE_STATES.find((entry) => entry === state) ?? null;
}

export const SERVICE_DOES_NOT_EXIST = 1060;
