import { invoke } from "@tauri-apps/api/core";
import { installTauriBridge } from "./bridge";
import { installWindowControls, type WindowAction } from "./window-controls";

installTauriBridge();
installWindowControls((action: WindowAction) => void invoke("window_control", { action }));

await import("../../shared/ui/src/main");

requestAnimationFrame(() => requestAnimationFrame(() => void invoke("window_control", { action: "ready" })));
