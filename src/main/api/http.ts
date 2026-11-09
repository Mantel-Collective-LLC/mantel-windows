import http from "node:http";
import https from "node:https";
import type { LookupFunction } from "node:net";

export type HttpResponse = {
  status: number;
  headers: Headers;
  text: string;
  tooLarge: boolean;
};

export type HttpRequestOptions = {
  method: string;
  headers: Record<string, string>;
  body?: string;
  timeoutMs: number;
  maxBytes: number;
  lookup?: LookupFunction;
};

function toHeaders(raw: http.IncomingHttpHeaders): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(raw)) {
    if (value === undefined) continue;
    for (const entry of Array.isArray(value) ? value : [value]) headers.append(name, entry);
  }
  return headers;
}

export function httpRequest(url: URL, options: HttpRequestOptions): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === "https:" ? https : url.protocol === "http:" ? http : null;
    if (!transport) {
      reject(new Error(`Nicht unterstütztes Protokoll: ${url.protocol}`));
      return;
    }
    let settled = false;
    const finish = (action: () => void) => {
      if (settled) return;
      settled = true;
      action();
    };
    const headers: Record<string, string> = { ...options.headers };
    if (options.body !== undefined) headers["Content-Length"] = String(Buffer.byteLength(options.body));
    const request = transport.request(
      url,
      {
        method: options.method,
        headers,
        agent: false,
        signal: AbortSignal.timeout(options.timeoutMs),
        ...(options.lookup ? { lookup: options.lookup } : {}),
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        const result = (text: string, tooLarge: boolean): HttpResponse => ({
          status: response.statusCode ?? 0,
          headers: toHeaders(response.headers),
          text,
          tooLarge,
        });
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > options.maxBytes) {
            finish(() => resolve(result("", true)));
            response.destroy();
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => finish(() => resolve(result(Buffer.concat(chunks).toString("utf8"), false))));
        response.on("error", (error) => finish(() => reject(error)));
        response.on("close", () => {
          if (!response.complete) finish(() => reject(new Error("Verbindung vorzeitig geschlossen.")));
        });
      },
    );
    request.on("error", (error) => finish(() => reject(error)));
    request.end(options.body);
  });
}
