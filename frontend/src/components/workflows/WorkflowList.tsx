import { useCallback, useEffect, useState } from "react";
import { Loader2, Workflow as WorkflowIcon, Plus, Clock } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { Textarea } from "@/components/ds/textarea";
import { Label } from "@/components/ds/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ds/dialog";
import { listWorkflows, createWorkflow, type Workflow } from "@/api/workflows";

function formatRelativeTime(dateStr: string | null): string {
  if (!dateStr) return "Never";
  const date = new Date(dateStr);
  const diffMs = Date.now() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

export function WorkflowList() {
  const [workflows, setWorkflows] = useState<Workflow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await listWorkflows({ page_size: 100 });
      setWorkflows(resp.items);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load workflows");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleCreate = useCallback(async () => {
    if (!name.trim()) return;
    setCreating(true);
    setCreateError(null);
    try {
      await createWorkflow({ name: name.trim(), description: description.trim() });
      setCreateOpen(false);
      setName("");
      setDescription("");
      await load();
    } catch (e) {
      setCreateError(e instanceof Error ? e.message : "Create failed");
    } finally {
      setCreating(false);
    }
  }, [name, description, load]);

  return (
    <>
      <Header title="Workflows" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="workflow-list">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-foreground">Workflows</h2>
            <p className="text-sm text-muted-foreground">
              Author, version, and run security workflows. Each workflow keeps a
              draft → published → deprecated version history.
            </p>
          </div>
          <Button onClick={() => setCreateOpen(true)} data-testid="workflow-create-open">
            <Plus className="w-4 h-4 mr-2" />
            New workflow
          </Button>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-muted-foreground text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
          </div>
        )}

        {error && (
          <div
            className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
            role="alert"
          >
            {error}
          </div>
        )}

        {!loading && !error && workflows.length === 0 && (
          <Card>
            <CardContent className="py-12 text-center text-muted-foreground">
              <WorkflowIcon className="w-8 h-8 mx-auto mb-3 opacity-50" />
              <p className="text-sm">No workflows yet. Create one to get started.</p>
            </CardContent>
          </Card>
        )}

        {!loading && workflows.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {workflows.map((wf) => (
              <Card key={wf.id} data-testid="workflow-card" data-workflow-id={wf.id}>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <WorkflowIcon className="w-4 h-4 text-primary shrink-0" />
                    <span className="truncate">{wf.name}</span>
                  </CardTitle>
                  {wf.description && (
                    <CardDescription className="line-clamp-2">
                      {wf.description}
                    </CardDescription>
                  )}
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Clock className="w-3 h-3" />
                    Updated {formatRelativeTime(wf.updated_at)}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New workflow</DialogTitle>
            <DialogDescription>
              Creates the workflow plus an empty draft version 1. You author the
              graph next on the canvas.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="wf-name">Name</Label>
              <Input
                id="wf-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Phishing triage"
                data-testid="workflow-name-input"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="wf-desc">Description</Label>
              <Textarea
                id="wf-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                placeholder="What this workflow does…"
              />
            </div>
            {createError && (
              <div
                className="rounded-md border border-destructive/30 bg-destructive/10 p-2.5 text-sm text-destructive"
                role="alert"
              >
                {createError}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setCreateOpen(false)} disabled={creating}>
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={creating || !name.trim()}
              data-testid="workflow-create-submit"
            >
              {creating ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Creating…
                </>
              ) : (
                "Create"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
