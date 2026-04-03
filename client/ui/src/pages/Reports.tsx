// src/pages/Reports.tsx
import { useProjects } from '../stores/projects';
import { Card, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { FileText, Download } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function Reports() {
  const project = useProjects((s) => s.getActive());
  const navigate = useNavigate();

  if (!project) {
    return (
      <div className="flex items-center justify-center h-full">
        <Button onClick={() => navigate('/projects')}>Select a Project</Button>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-4">
      <h1 className="text-lg font-bold text-text-primary">Reports — {project.name}</h1>

      <div className="grid grid-cols-3 gap-3">
        {['PDF Report', 'HTML Report', 'SARIF Export'].map((type) => (
          <Card key={type} hover className="flex flex-col items-center py-6 gap-3">
            <FileText size={24} className="text-pf-400" />
            <span className="text-sm font-medium text-text-primary">{type}</span>
            <Button size="sm" variant="secondary">
              <Download size={12} /> Generate
            </Button>
          </Card>
        ))}
      </div>
    </div>
  );
}