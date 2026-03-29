import { useState } from "react";

import { Dialog } from "@/components/ui/Dialog";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";

export function NewProjectDialog({
  open,
  onClose,
  onCreate
}: {
  open: boolean;
  onClose: () => void;
  onCreate: (payload: { name: string; target: string; targetType: string }) => void;
}) {
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [targetType, setTargetType] = useState("web_app");

  return (
    <Dialog open={open} onClose={onClose} title="Create New Project">
      <div className="space-y-3">
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Project name" />
        <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Target URL / IP" />
        <Select
          value={targetType}
          onChange={(event) => setTargetType(event.target.value)}
          options={[
            { value: "web_app", label: "Web App" },
            { value: "api", label: "API" },
            { value: "infra", label: "Infrastructure" },
            { value: "network", label: "Network" }
          ]}
        />
        <div className="flex justify-end">
          <Button
            onClick={() => {
              onCreate({ name, target, targetType });
              onClose();
              setName("");
              setTarget("");
              setTargetType("web_app");
            }}
            disabled={!name.trim() || !target.trim()}
          >
            Create
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
