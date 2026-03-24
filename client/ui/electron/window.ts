import { BrowserWindow, shell } from "electron";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createMainWindow() {
  const preloadPathMjs = path.join(__dirname, "preload.mjs");
  const preloadPathJs = path.join(__dirname, "preload.js");

  const win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1200,
    minHeight: 760,
    frame: false,
    titleBarStyle: "hiddenInset",
    webPreferences: {
      preload: existsSync(preloadPathMjs) ? preloadPathMjs : preloadPathJs
    }
  });

  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  return win;
}
