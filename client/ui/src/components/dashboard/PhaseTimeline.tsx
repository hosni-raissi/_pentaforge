import { motion } from "framer-motion";

import { Card } from "@/components/ui/Card";

const phases = ["Reconnaissance", "Enumeration", "Exploitation", "Post-Exploitation", "Reporting"];

export function PhaseTimeline() {
  return (
    <Card>
      <h3 className="mb-3 text-sm font-semibold">Phase Timeline</h3>
      <div className="space-y-2">
        {phases.map((phase, idx) => (
          <motion.div
            key={phase}
            initial={{ opacity: 0, x: -12 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.05 }}
            className="rounded-md border border-border px-3 py-2 text-sm"
          >
            {idx + 1}. {phase}
          </motion.div>
        ))}
      </div>
    </Card>
  );
}
