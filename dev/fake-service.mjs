import net from "node:net";

export const FAKE_SERVICE_PIPE = "\\\\.\\pipe\\mantel-service-debug";

function answer(request) {
  switch (request.op) {
    case "hello":
      return { ok: true, protocol: 1, flavor: "debug", version: "fake" };
    case "status":
      return {
        ok: true,
        service: { exists: false },
        wireguard: { directory: "C:\\Program Files\\WireGuard", source: "system" },
        tunnel: { running: false, peers: [] },
      };
    case "killswitch-status":
      return { ok: true, killSwitchRules: 0 };
    default:
      return { ok: false, error: "invalid", detail: `fake service: ${request.op} is not simulated` };
  }
}

function pipeTaken() {
  return new Promise((resolve) => {
    const probe = net.connect(FAKE_SERVICE_PIPE);
    probe.once("connect", () => {
      probe.destroy();
      resolve(true);
    });
    probe.once("error", () => resolve(false));
  });
}

export async function startFakeService() {
  if (await pipeTaken()) throw new Error(`${FAKE_SERVICE_PIPE} ist schon belegt (echter Debug-Dienst?)`);
  const server = net.createServer((socket) => {
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
      const end = data.indexOf("\n");
      if (end < 0) return;
      let request = {};
      try {
        request = JSON.parse(data.slice(0, end));
      } catch {
      }
      socket.end(`${JSON.stringify(answer(request))}\n`);
    });
    socket.on("error", () => undefined);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(FAKE_SERVICE_PIPE, () => resolve(server));
  });
}

if (import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, "/")}`) {
  await startFakeService();
  console.log(`fake service on ${FAKE_SERVICE_PIPE}`);
}
