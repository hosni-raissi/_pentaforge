import { BrowserWindow as e, app as t, ipcMain as n, shell as r } from "electron";
import i from "node:path";
import { existsSync as a } from "node:fs";
import { fileURLToPath as o } from "node:url";
//#region electron/window.ts
var s = o(import.meta.url), c = i.dirname(s);
function l() {
	let t = i.join(c, "preload.mjs"), n = i.join(c, "preload.js"), o = new e({
		width: 1440,
		height: 900,
		minWidth: 1200,
		minHeight: 760,
		frame: !1,
		titleBarStyle: "hiddenInset",
		webPreferences: { preload: a(t) ? t : n }
	});
	return o.webContents.setWindowOpenHandler(({ url: e }) => (r.openExternal(e), { action: "deny" })), o;
}
//#endregion
//#region electron/main.ts
var u = null, d = !t.isPackaged;
async function f() {
	u = l(), n.handle("window:minimize", () => u?.minimize()), n.handle("window:maximize", () => {
		u && (u.isMaximized() ? u.unmaximize() : u.maximize());
	}), n.handle("window:close", () => u?.close()), d ? (await u.loadURL("http://localhost:5173"), u.webContents.openDevTools({ mode: "detach" })) : await u.loadFile(i.join(t.getAppPath(), "dist", "index.html"));
}
t.whenReady().then(() => {
	f().catch((e) => {
		console.error("[electron] bootstrap failed", e);
	});
}), process.on("unhandledRejection", (e) => {
	console.error("[electron] unhandled rejection", e);
}), t.on("window-all-closed", () => {
	process.platform !== "darwin" && t.quit();
}), t.on("activate", () => {
	u || f().catch((e) => {
		console.error("[electron] bootstrap failed", e);
	});
});
//#endregion
