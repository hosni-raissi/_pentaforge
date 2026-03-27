import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { AppConfig, LLMConfig } from '../types';

interface ConfigStore extends AppConfig {
  updateConfig: (updates: Partial<AppConfig>) => void;
  addLLM: (config: LLMConfig) => void;
  removeLLM: (id: string) => void;
  updateLLM: (id: string, updates: Partial<LLMConfig>) => void;
  setActiveLLM: (id: string) => void;
}

const DEFAULT_LLM: LLMConfig = {
  id: 'default-groq',
  name: 'Groq — Llama 3.3 70B',
  provider: 'groq',
  model: 'llama-3.3-70b-versatile',
  apiKey: '',
  baseUrl: 'https://api.groq.com/openai/v1',
  maxTokens: 4096,
  temperature: 0.3,
  isDefault: true,
  mode: 'public',
};

export const useConfig = create<ConfigStore>()(
  persist(
    (set) => ({
      llmConfigs: [DEFAULT_LLM],
      activeLLM: 'default-groq',
      serverUrl: 'http://localhost',
      serverPort: 8000,
      autoApprove: false,
      stealthMode: false,

      updateConfig: (updates) => set(updates),

      addLLM: (config) =>
        set((s) => ({ llmConfigs: [...s.llmConfigs, config] })),

      removeLLM: (id) =>
        set((s) => ({
          llmConfigs: s.llmConfigs.filter((c) => c.id !== id),
          activeLLM: s.activeLLM === id ? s.llmConfigs[0]?.id ?? '' : s.activeLLM,
        })),

      updateLLM: (id, updates) =>
        set((s) => ({
          llmConfigs: s.llmConfigs.map((c) => (c.id === id ? { ...c, ...updates } : c)),
        })),

      setActiveLLM: (id) => set({ activeLLM: id }),
    }),
    {
      name: 'pf-config',
      merge: (persisted, current) => {
        const state = (persisted ?? {}) as Partial<AppConfig>;
        const llmConfigs = Array.isArray(state.llmConfigs)
          ? state.llmConfigs.filter((item): item is LLMConfig => {
            if (typeof item !== 'object' || item === null) {
              return false;
            }
            return typeof item.id === 'string' && typeof item.name === 'string';
          })
          : current.llmConfigs;
        const safeConfigs = llmConfigs.length > 0 ? llmConfigs : current.llmConfigs;
        const requestedActive = typeof state.activeLLM === 'string' ? state.activeLLM : current.activeLLM;
        const activeLLM = safeConfigs.some((item) => item.id === requestedActive)
          ? requestedActive
          : safeConfigs[0]?.id ?? current.activeLLM;

        return {
          ...current,
          ...state,
          llmConfigs: safeConfigs,
          activeLLM,
          serverUrl: typeof state.serverUrl === 'string' ? state.serverUrl : current.serverUrl,
          serverPort: typeof state.serverPort === 'number' ? state.serverPort : current.serverPort,
          autoApprove: typeof state.autoApprove === 'boolean' ? state.autoApprove : current.autoApprove,
          stealthMode: typeof state.stealthMode === 'boolean' ? state.stealthMode : current.stealthMode,
        };
      },
    }
  )
);
