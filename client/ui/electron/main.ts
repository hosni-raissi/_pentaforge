import { app, ipcMain } from "electron";
import path from "node:path";

import { createMainWindow } from "./window";

let mainWindow: ReturnType<typeof createMainWindow> | null = null;

const isDev = !app.isPackaged;

async function bootstrap() {
  mainWindow = createMainWindow();

  ipcMain.handle("window:minimize", () => mainWindow?.minimize());
  ipcMain.handle("window:maximize", () => {
    if (!mainWindow) {
      return;
    }
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
  });
  ipcMain.handle("window:close", () => mainWindow?.close());

  if (isDev) {
    await mainWindow.loadURL("http://localhost:5173");
    mainWindow.webContents.openDevTools({ mode: "detach" });
  } else {
    await mainWindow.loadFile(path.join(app.getAppPath(), "dist", "index.html"));
  }
}

app.whenReady().then(() => {
  void bootstrap().catch((error) => {
    console.error("[electron] bootstrap failed", error);
  });
});
process.on("unhandledRejection", (error) => {
  console.error("[electron] unhandled rejection", error);
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("activate", () => {
  if (!mainWindow) {
    void bootstrap().catch((error) => {
      console.error("[electron] bootstrap failed", error);
    });
  }
});
