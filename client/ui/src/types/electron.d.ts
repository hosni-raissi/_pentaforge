export {};

declare global {
  interface Window {
    desktop?: {
      window: {
        minimize: () => Promise<void> | void;
        maximize: () => Promise<void> | void;
        close: () => Promise<void> | void;
      };
    };
  }
}
