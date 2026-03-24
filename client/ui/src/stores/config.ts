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
    { name: 'pf-config' }
  )
);