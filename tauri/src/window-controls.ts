import { THEME_INK, type Theme } from "../../shared/core/theme";

export type WindowAction = "minimize" | "toggle-maximize" | "close" | "drag";

const SVG = "http://www.w3.org/2000/svg";
const BUTTON_WIDTH = 46;
const BAR_HEIGHT = 40;

const GLYPHS: Record<"minimize" | "maximize" | "close", string[]> = {
  minimize: ["M0 5.5 H10"],
  maximize: ["M0.5 0.5 H9.5 V9.5 H0.5 Z"],
  close: ["M0 0 L10 10", "M10 0 L0 10"],
};

function glyph(kind: keyof typeof GLYPHS): SVGSVGElement {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("width", "10");
  svg.setAttribute("height", "10");
  svg.setAttribute("viewBox", "0 0 10 10");
  svg.setAttribute("aria-hidden", "true");
  for (const d of GLYPHS[kind]) {
    const path = document.createElementNS(SVG, "path");
    path.setAttribute("d", d);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", "currentColor");
    path.setAttribute("stroke-width", "1");
    svg.appendChild(path);
  }
  return svg;
}

function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

export function startsDrag(target: Element | null): boolean {
  if (!target?.closest(".app-drag")) return false;
  return !target.closest(".app-no-drag, button, a, input, textarea, select, [role='button']");
}

export function installWindowControls(action: (name: WindowAction) => void): void {
  const bar = document.createElement("div");
  bar.dataset.tauriWindowControls = "";
  Object.assign(bar.style, {
    position: "fixed",
    top: "0",
    right: "0",
    height: `${BAR_HEIGHT}px`,
    display: "flex",
    zIndex: "2147483647",
  });
  const buttons: HTMLButtonElement[] = [];
  const add = (kind: keyof typeof GLYPHS, name: WindowAction, label: string) => {
    const button = document.createElement("button");
    button.type = "button";
    button.tabIndex = -1;
    button.setAttribute("aria-label", label);
    button.dataset.kind = kind;
    Object.assign(button.style, {
      width: `${BUTTON_WIDTH}px`,
      height: `${BAR_HEIGHT}px`,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      border: "0",
      padding: "0",
      margin: "0",
      background: "transparent",
      cursor: "default",
      outline: "none",
    });
    button.appendChild(glyph(kind));
    button.addEventListener("click", () => action(name));
    button.addEventListener("mouseenter", () => paint(button, true));
    button.addEventListener("mouseleave", () => paint(button, false));
    buttons.push(button);
    bar.appendChild(button);
  };

  const paint = (button: HTMLButtonElement, hover: boolean) => {
    const theme = currentTheme();
    const close = button.dataset.kind === "close";
    button.style.color = hover && close ? "#ffffff" : THEME_INK[theme];
    button.style.background = !hover ? "transparent" : close ? "#c42b1c" : theme === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.06)";
  };

  add("minimize", "minimize", "Minimize");
  add("maximize", "toggle-maximize", "Maximize");
  add("close", "close", "Close");
  const repaint = () => buttons.forEach((button) => paint(button, button.matches(":hover")));
  repaint();
  new MutationObserver(repaint).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

  document.addEventListener("mousedown", (event) => {
    if (event.button !== 0 || !startsDrag(event.target as Element | null)) return;
    if (event.detail === 2) action("toggle-maximize");
    else action("drag");
  });

  const mount = () => document.body.appendChild(bar);
  if (document.body) mount();
  else document.addEventListener("DOMContentLoaded", mount, { once: true });
}
