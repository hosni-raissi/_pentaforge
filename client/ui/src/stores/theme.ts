import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface ThemeStore {
  isDark: boolean;
  toggle: () => void;
  setDark: (dark: boolean) => void;
}

export const useTheme = create<ThemeStore>()(
  persist(
    (set) => ({
      isDark: true, // Default to dark mode
      toggle: () =>
        set((s) => {
          const next = !s.isDark;
          document.documentElement.classList.toggle('dark', next);
          return { isDark: next };
        }),
      setDark: (dark) => {
        document.documentElement.classList.toggle('dark', dark);
        set({ isDark: dark });
      },
    }),
    {
      name: 'pf-theme',
      onRehydrateStorage: () => (state) => {
        if (state) {
          document.documentElement.classList.toggle('dark', state.isDark);
        }
      },
    }
  )
);