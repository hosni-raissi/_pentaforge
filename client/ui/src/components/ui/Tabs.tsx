import { useState, type ReactNode } from 'react';
import { cn } from '../../lib/utils';
import { motion } from 'framer-motion';

interface Tab {
  id: string;
  label: string;
  icon?: ReactNode;
  content: ReactNode;
}

interface TabsProps {
  tabs: Tab[];
  defaultTab?: string;
  className?: string;
}

export function Tabs({ tabs, defaultTab, className }: TabsProps) {
  const [active, setActive] = useState(defaultTab ?? tabs[0]?.id ?? '');
  const activeTab = tabs.find((t) => t.id === active);

  return (
    <div className={className}>
      <div className="flex items-center gap-0.5 border-b border-border mb-4">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActive(tab.id)}
            className={cn(
              'relative flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors',
              active === tab.id ? 'text-pf-400' : 'text-text-muted hover:text-text-secondary'
            )}
          >
            {tab.icon}
            {tab.label}
            {active === tab.id && (
              <motion.div
                layoutId="tab-indicator"
                className="absolute bottom-0 left-0 right-0 h-0.5 bg-pf-500 rounded-full"
                transition={{ duration: 0.2 }}
              />
            )}
          </button>
        ))}
      </div>
      <div>{activeTab?.content}</div>
    </div>
  );
}