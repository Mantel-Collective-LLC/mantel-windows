import { Menu, type MenuItemConstructorOptions } from "electron";
import type { Dictionary } from "../../shared/core/i18n";

export function macMenuTemplate(input: {
  t: Dictionary;
  format: (text: string, params: Record<string, string | number>) => string;
  productName: string;
  debug: boolean;
  onShowWindow: () => void;
}): MenuItemConstructorOptions[] {
  const m = input.t.mac.menu;
  const name = { name: input.productName };
  const view: MenuItemConstructorOptions[] = input.debug
    ? [{ label: m.view, submenu: [{ label: m.devTools, role: "toggleDevTools" }] }]
    : [];
  return [
    {
      label: input.productName,
      submenu: [
        { label: input.format(m.about, name), role: "about" },
        { type: "separator" },
        { label: input.format(m.hide, name), role: "hide" },
        { label: m.hideOthers, role: "hideOthers" },
        { label: m.showAll, role: "unhide" },
        { type: "separator" },
        { label: input.format(m.quit, name), role: "quit" },
      ],
    },
    {
      label: m.edit,
      submenu: [
        { label: m.undo, role: "undo" },
        { label: m.redo, role: "redo" },
        { type: "separator" },
        { label: m.cut, role: "cut" },
        { label: m.copy, role: "copy" },
        { label: m.paste, role: "paste" },
        { label: m.selectAll, role: "selectAll" },
      ],
    },
    ...view,
    {
      label: m.window,
      role: "windowMenu",
      submenu: [
        { label: m.minimize, role: "minimize" },
        { label: m.zoom, role: "zoom" },
        { label: m.close, role: "close" },
        { type: "separator" },
        { label: input.productName, click: input.onShowWindow },
        { label: m.front, role: "front" },
      ],
    },
  ];
}

export function applyMacMenu(input: Parameters<typeof macMenuTemplate>[0]): void {
  Menu.setApplicationMenu(Menu.buildFromTemplate(macMenuTemplate(input)));
}
