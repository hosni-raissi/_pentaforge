import { useMemo, useState } from 'react';
import { Bot, SendHorizontal, Sparkles } from 'lucide-react';

import type { AgentInfo } from '../../types';
import { Button } from '../ui/Button';
import { Card, CardHeader, CardTitle } from '../ui/Card';

interface AIPromptPanelProps {
  projectName: string;
  target: string;
  agents: AgentInfo[];
}

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  text: string;
}

const quickPrompts = [
  'What should I do next?',
  'Summarize current agent state',
  'Show highest risk findings',
];

export function AIPromptPanel({ projectName, target, agents }: AIPromptPanelProps) {
  const [prompt, setPrompt] = useState('');
  const [sending, setSending] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'intro',
      role: 'assistant',
      text: `AI Copilot online for ${projectName}. Ask anything about ${target}.`,
    },
  ]);

  const runningAgent = useMemo(
    () => agents.find((agent) => agent.state === 'running'),
    [agents]
  );

  const buildReply = () => {
    if (runningAgent) {
      return `Current active agent is ${runningAgent.name}. Task: ${runningAgent.currentTask ?? 'in progress'}.`;
    }
    return 'No agent is actively running right now. You can start scan flow from Scan Control.';
  };

  const sendPrompt = (text: string) => {
    const clean = text.trim();
    if (!clean || sending) return;

    const userMessage: ChatMessage = {
      id: `u-${Date.now()}`,
      role: 'user',
      text: clean,
    };
    setMessages((prev) => [...prev, userMessage]);
    setPrompt('');
    setSending(true);

    window.setTimeout(() => {
      const aiMessage: ChatMessage = {
        id: `a-${Date.now()}`,
        role: 'assistant',
        text: buildReply(),
      };
      setMessages((prev) => [...prev, aiMessage]);
      setSending(false);
    }, 450);
  };

  return (
    <Card className="flex h-[340px] flex-col">
      <CardHeader className="mb-2">
        <div>
          <CardTitle>Interact with AI</CardTitle>
          <p className="mt-1 text-xs text-text-secondary">
            Prompt the copilot for next steps, summaries, and actions.
          </p>
        </div>
        <Sparkles size={14} className="text-pf-400" />
      </CardHeader>

      <div className="mb-3 flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto rounded-md border border-border bg-surface-0 p-2">
        {messages.map((message) => (
          <div
            key={message.id}
            className={
              message.role === 'assistant'
                ? 'max-w-[92%] rounded-md border border-pf-500/20 bg-pf-500/10 p-2 text-xs text-text-primary'
                : 'ml-auto max-w-[92%] rounded-md border border-border bg-surface-2 p-2 text-xs text-text-primary'
            }
          >
            {message.role === 'assistant' && (
              <div className="mb-1 flex items-center gap-1 text-[10px] font-semibold text-pf-400">
                <Bot size={11} />
                Copilot
              </div>
            )}
            <p>{message.text}</p>
          </div>
        ))}
      </div>

      <div className="mb-2 flex flex-wrap gap-1.5">
        {quickPrompts.map((quick) => (
          <Button
            key={quick}
            variant="secondary"
            size="xs"
            type="button"
            onClick={() => sendPrompt(quick)}
            disabled={sending}
          >
            {quick}
          </Button>
        ))}
      </div>

      <div className="flex items-end gap-2">
        <textarea
          value={prompt}
          onChange={(event) => setPrompt(event.target.value)}
          placeholder="Ask AI for strategy, scope checks, or next step..."
          className="focus-ring min-h-[44px] flex-1 resize-none rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary placeholder:text-text-muted"
          rows={2}
        />
        <Button
          type="button"
          onClick={() => sendPrompt(prompt)}
          disabled={sending || !prompt.trim()}
          loading={sending}
          size="sm"
        >
          <SendHorizontal size={14} />
          Send
        </Button>
      </div>
    </Card>
  );
}
