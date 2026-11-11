import { useCallback, useEffect, useState, type FormEvent } from "react";
import { WarningIcon } from "@phosphor-icons/react";
import type { Account, Device, MantelBridge, PortForward, PortForwardingState, Result, VpnNode } from "../../../core/contract";
import { useI18n } from "../i18n/context";
import { cn } from "../lib/cn";
import { Flag } from "../ui/flag";
import { CopyButton, DeviceKindIcon, deviceKind, EmptyState, FIELD, PageHeader } from "../ui/manage";
import { Badge, Button, Card, InlineError } from "../ui/primitives";

export function parseLocalPort(text: string): number | null | undefined {
  const value = text.trim();
  if (value === "") return null;
  if (!/^\d{1,5}$/.test(value)) return undefined;
  const port = Number(value);
  return port >= 1 && port <= 65535 ? port : undefined;
}

export function publishPort(
  bridge: MantelBridge,
  deviceId: string,
  text: string,
  localSupported: boolean,
): Promise<Result<PortForwardingState | null>> | null {
  const localPort = parseLocalPort(text);
  if (localPort === undefined || (localPort !== null && !localSupported) || !bridge.addPortForward) return null;
  return bridge.addPortForward(deviceId, localPort);
}

export type ForwardsLoad = { kind: "loading" } | { kind: "ready"; state: PortForwardingState | null } | { kind: "failed"; error: string };

export function PortForwardsPage({
  bridge,
  account,
  nodes,
  onShowConnect,
}: {
  bridge: MantelBridge;
  account: Account;
  nodes: readonly VpnNode[];
  onShowConnect: () => void;
}) {
  const { t } = useI18n();
  const devices = account.devices;
  const [ownId, setOwnId] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    void bridge.currentDeviceId?.().then((id) => alive && setOwnId(id));
    return () => {
      alive = false;
    };
  }, [bridge]);
  return (
    <div className="space-y-4">
      <PageHeader title={t.forwards.title} description={t.forwards.description} />
      {devices.length === 0 ? (
        <EmptyState
          title={t.forwards.emptyTitle}
          text={t.forwards.empty}
          action={
            <Button variant="secondary" onClick={onShowConnect}>
              {t.manage.toConnect}
            </Button>
          }
        />
      ) : (
        <>
          {devices.map((device) => (
            <DeviceForwards
              key={device.id}
              bridge={bridge}
              device={device}
              own={device.id === ownId}
              node={nodes.find((node) => node.id === device.nodeId) ?? null}
            />
          ))}
          <ForwardNotes />
        </>
      )}
    </div>
  );
}

export function ForwardNotes() {
  const { t } = useI18n();
  return (
    <div className="space-y-3 px-1">
      <ul className="list-disc space-y-1 pl-4 text-[12.5px] leading-relaxed text-zinc-500 marker:text-zinc-300">
        <li>{t.forwards.listenHint}</li>
        <li>{t.forwards.connectedNote}</li>
        <li>{t.forwards.switchNote}</li>
      </ul>
      <p className="flex items-start gap-1.5 text-[12.5px] leading-relaxed text-amber-700">
        <WarningIcon weight="fill" className="mt-0.5 size-4 shrink-0" aria-hidden />
        {t.forwards.warning}
      </p>
      <details className="group rounded-2xl border border-zinc-200/80 px-3.5 py-2.5">
        <summary className="cursor-pointer text-[13px] text-ink outline-none focus-visible:ring-2 focus-visible:ring-accent">
          {t.forwards.torrentTitle}
        </summary>
        <p className="mt-2 text-[12.5px] leading-relaxed text-zinc-500">{t.forwards.hint}</p>
      </details>
    </div>
  );
}

function DeviceForwards({ bridge, device, node, own }: { bridge: MantelBridge; device: Device; node: VpnNode | null; own: boolean }) {
  const [load, setLoad] = useState<ForwardsLoad>({ kind: "loading" });
  const [pending, setPending] = useState<number | "add" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [localText, setLocalText] = useState("");

  const read = useCallback(async () => {
    const result = await bridge.devicePortForwarding?.(device.id);
    if (!result) return;
    setLoad(result.ok ? { kind: "ready", state: result.value } : { kind: "failed", error: result.error });
  }, [bridge, device.id]);

  useEffect(() => {
    void read();
  }, [read]);

  const run = async (action: number | "add", call: Promise<Result<PortForwardingState | null>> | null | undefined): Promise<boolean> => {
    if (!call) return false;
    setPending(action);
    setError(null);
    const result = await call;
    setPending(null);
    if (result.ok) setLoad({ kind: "ready", state: result.value });
    else setError(result.error);
    return result.ok;
  };

  const localSupported = load.kind === "ready" && load.state?.localPort === true;
  return (
    <DeviceForwardsView
      bridge={bridge}
      device={device}
      node={node}
      own={own}
      load={load}
      pending={pending}
      error={error}
      localText={localText}
      onLocalText={setLocalText}
      onPublish={() =>
        void run("add", publishPort(bridge, device.id, localText, localSupported)).then((ok) => ok && setLocalText(""))
      }
      onRemove={(port) => void run(port, bridge.removePortForward?.(device.id, port))}
      onSaveLocal={(port, value) => run(port, bridge.setPortForwardLocalPort?.(device.id, port, value))}
      onRetry={() => void read()}
    />
  );
}

export function DeviceForwardsView({
  bridge,
  device,
  node,
  own,
  load,
  pending,
  error,
  localText,
  onLocalText,
  onPublish,
  onRemove,
  onSaveLocal,
  onRetry,
}: {
  bridge: MantelBridge;
  device: Device;
  node: VpnNode | null;
  own: boolean;
  load: ForwardsLoad;
  pending: number | "add" | null;
  error: string | null;
  localText: string;
  onLocalText: (text: string) => void;
  onPublish: () => void;
  onRemove: (port: number) => void;
  onSaveLocal: (port: number, value: number | null) => Promise<boolean>;
  onRetry: () => void;
}) {
  const { t, format } = useI18n();
  const state = load.kind === "ready" ? load.state : null;
  const forwards = state?.forwards ?? [];
  const city = state?.city ?? node?.city ?? t.devices.unknownLocation;
  const reasons = t.settings.portForwardingReasons;
  const reason = state?.reason ? format(reasons[state.reason] ?? reasons.unsupported, { city }) : null;
  const localPort = parseLocalPort(localText);
  const unsupported = typeof localPort === "number" && state !== null && !state.localPort;
  const showForm = state !== null && state.available && forwards.length < state.max;
  const canPublish = localPort !== undefined && !unsupported && pending === null;
  const target = own ? t.forwards.thisDevice : device.name;
  const editable = state?.localPort === true && bridge.setPortForwardLocalPort !== undefined;
  const id = `pf-local-${device.id}`;
  const fieldProblem = localPort === undefined ? t.forwards.localPortInvalid : unsupported ? format(t.forwards.localUnsupported, { city }) : null;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (canPublish) onPublish();
  };

  return (
    <Card className="overflow-hidden">
      <section aria-label={device.name}>
        <header className="flex items-center gap-3 border-b border-zinc-100 px-4 py-3">
          <span aria-hidden className="grid size-9 shrink-0 place-items-center rounded-xl bg-zinc-100 text-zinc-700">
            <DeviceKindIcon kind={deviceKind(device.name)} className="size-[18px]" />
          </span>
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-[15px] tracking-[-0.01em] text-ink">{device.name}</h2>
            <p className="mt-0.5 flex items-center gap-1.5 text-[12.5px] text-zinc-500">
              {node && <Flag code={node.country} className="size-3.5" />}
              {city}
            </p>
          </div>
          {state && <Badge>{format(t.forwards.count, { count: forwards.length, max: state.max })}</Badge>}
        </header>
        <div className="space-y-3 px-4 py-3">
          {load.kind === "loading" && <span className="block h-10 animate-pulse rounded-2xl bg-zinc-100" />}
          {load.kind === "ready" && state === null && <p className="text-[13px] text-zinc-500">{t.forwards.noForward}</p>}
          {reason && <p className="text-[13px] leading-relaxed text-zinc-600">{reason}</p>}
          {forwards.map((forward) => (
            <ForwardRow
              key={forward.port}
              bridge={bridge}
              forward={forward}
              target={target}
              editable={editable}
              pending={pending}
              onRemove={() => onRemove(forward.port)}
              onSaveLocal={(value) => onSaveLocal(forward.port, value)}
            />
          ))}
          {showForm && (
            <form onSubmit={submit} className="space-y-1.5" noValidate>
              <label htmlFor={id} className="block text-[12.5px] font-medium text-zinc-600">
                {t.forwards.localPort}
              </label>
              <div className="flex items-center gap-2">
                <input
                  id={id}
                  inputMode="numeric"
                  autoComplete="off"
                  maxLength={5}
                  value={localText}
                  placeholder={t.forwards.localPortPlaceholder}
                  aria-invalid={fieldProblem !== null || undefined}
                  aria-describedby={`${id}-help`}
                  onChange={(event) => onLocalText(event.target.value)}
                  className={cn(FIELD, "h-11 max-w-32 py-0 font-mono tabular-nums", fieldProblem !== null && "border-red-400")}
                />
                <Button type="submit" pending={pending === "add"} disabled={!canPublish}>
                  {t.forwards.add}
                </Button>
              </div>
              <p id={`${id}-help`} aria-live="polite" className={cn("text-[12.5px] leading-relaxed", fieldProblem ? "text-red-600" : "text-zinc-500")}>
                {fieldProblem ?? t.forwards.localPortHelp}
              </p>
            </form>
          )}
          {state?.available && forwards.length >= state.max && (
            <p className="text-[12.5px] text-zinc-500">{format(t.forwards.limitNote, { max: state.max })}</p>
          )}
          <InlineError message={load.kind === "failed" ? load.error : error} />
          {load.kind === "failed" && (
            <Button variant="ghost" size="sm" onClick={onRetry}>
              {t.manage.retry}
            </Button>
          )}
        </div>
      </section>
    </Card>
  );
}

function ForwardRow({
  bridge,
  forward,
  target,
  editable,
  pending,
  onRemove,
  onSaveLocal,
}: {
  bridge: MantelBridge;
  forward: PortForward;
  target: string;
  editable: boolean;
  pending: number | "add" | null;
  onRemove: () => void;
  onSaveLocal: (value: number | null) => Promise<boolean>;
}) {
  const { t, format } = useI18n();
  const [editing, setEditing] = useState(false);
  const address = `${forward.host}:${forward.port}`;
  return (
    <div className="rounded-2xl border border-zinc-200/80 bg-zinc-50/60 px-3.5 py-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[11.5px] text-zinc-500">{t.forwards.publicAddress}</p>
          <p className="mt-0.5 flex flex-wrap items-baseline gap-x-2 [overflow-wrap:anywhere]">
            <span className="select-all font-mono text-[17px] tabular-nums tracking-[-0.02em] text-ink">{address}</span>
            <span className="text-[14px] tabular-nums text-zinc-600">
              {format(t.forwards.leadsTo, { device: target, port: forward.localPort ?? forward.port })}
            </span>
          </p>
          <p className="mt-0.5 text-[11.5px] text-zinc-400">{t.settings.portForwardingProtocols}</p>
        </div>
        <CopyButton bridge={bridge} text={address} label={`${t.forwards.publicAddress} ${address}`} compact />
      </div>
      {editing ? (
        <LocalPortEditor forward={forward} disabled={pending !== null} onSave={onSaveLocal} onDone={() => setEditing(false)} />
      ) : (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {editable && (
            <Button variant="secondary" size="sm" disabled={pending !== null} onClick={() => setEditing(true)}>
              {t.forwards.changeLocal}
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            aria-label={format(t.forwards.remove, { port: forward.port })}
            pending={pending === forward.port}
            disabled={pending !== null}
            onClick={onRemove}
          >
            {t.forwards.unpublish}
          </Button>
        </div>
      )}
    </div>
  );
}

function LocalPortEditor({
  forward,
  disabled,
  onSave,
  onDone,
}: {
  forward: PortForward;
  disabled: boolean;
  onSave: (value: number | null) => Promise<boolean>;
  onDone: () => void;
}) {
  const { t, format } = useI18n();
  const [text, setText] = useState(forward.localPort === null ? "" : String(forward.localPort));
  const value = parseLocalPort(text);
  const normalized = value === forward.port ? null : value;
  const dirty = value !== undefined && normalized !== forward.localPort;
  const id = `pf-edit-${forward.port}`;
  const save = (event: FormEvent) => {
    event.preventDefault();
    if (dirty && !disabled) void onSave(normalized ?? null).then((ok) => ok && onDone());
  };
  return (
    <form onSubmit={save} className="mt-2 space-y-1" noValidate>
      <label htmlFor={id} className="block text-[12.5px] font-medium text-zinc-600">
        {format(t.forwards.localPortFor, { port: forward.port })}
      </label>
      <div className="flex flex-wrap items-center gap-2">
        <input
          id={id}
          inputMode="numeric"
          autoComplete="off"
          maxLength={5}
          value={text}
          placeholder={t.forwards.localPortPlaceholder}
          aria-invalid={value === undefined || undefined}
          onChange={(event) => setText(event.target.value)}
          className={cn(FIELD, "h-9 max-w-32 py-0 font-mono tabular-nums", value === undefined && "border-red-400")}
        />
        <Button type="submit" variant="secondary" size="sm" disabled={!dirty || disabled}>
          {t.forwards.save}
        </Button>
        <Button variant="ghost" size="sm" onClick={onDone}>
          {t.forwards.cancel}
        </Button>
      </div>
      {value === undefined && <p className="text-[12.5px] text-red-600">{t.forwards.localPortInvalid}</p>}
    </form>
  );
}
