/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_WEB_PASSWORD?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
