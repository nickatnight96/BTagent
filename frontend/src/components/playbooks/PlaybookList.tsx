import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Workflow,
  Plus,
  Play,
  Search,
  Clock,
  Zap,
  BarChart3,
  MoreVertical,
  Pencil,
  Trash2,
} from "lucide-react";
import { clsx } from "clsx";
import { usePlaybookStore } from "@/stores/playbookStore";
import { TriggerType, type Playbook, type CreatePlaybookRequest } from "@/types/playbook";
import { deletePlaybook as apiDeletePlaybook, updatePlaybook as apiUpdatePlaybook } from "@/api/playbooks";

const TRIGGER_BADGES: Record<string, { label: string; className: string }> = {
  [TriggerType.ALERT_SEVERITY]: {
    label: "Alert",
    className: "bg-destructive/20 text-destructive border-red-500/30",
  },
  [TriggerType.IOC_TYPE]: {
    label: "IOC",
    className: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  },
  [TriggerType.MANUAL]: {
    label: "Manual",
    className: "bg-primary/20 text-primary border-primary/30",
  },
  [TriggerType.WEBHOOK]: {
    label: "Webhook",
    className: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  },
  [TriggerType.SCHEDULE]: {
    label: "Schedule",
    className: "bg-green-500/20 text-green-400 border-green-500/30",
  },
};

function formatRelativeTime(dateStr: string | null): string {
  if (!dateStr) return "Never";
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

export function PlaybookList() {
  const navigate = useNavigate();
  const { playbooks, isLoading, error, fetchPlaybooks, createPlaybook, clearBuilder } =
    usePlaybookStore();
  const [searchQuery, setSearchQuery] = useState("");
  const [menuOpenId, setMenuOpenId] = useState<string | null>(null);

  useEffect(() => {
    fetchPlaybooks();
  }, [fetchPlaybooks]);

  const filteredPlaybooks = playbooks.filter(
    (p) =>
      (p.name ?? "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      (p.description ?? "").toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const handleNewPlaybook = useCallback(async () => {
    clearBuilder();
    try {
      const data: CreatePlaybookRequest = {
        name: "Untitled Playbook",
        description: "",
        trigger: { type: TriggerType.MANUAL, parameters: {} },
        steps: [],
      };
      const playbook = await createPlaybook(data);
      navigate(`/playbooks/builder/${playbook.id}`);
    } catch {
      // Error handled by store
      navigate("/playbooks/builder");
    }
  }, [clearBuilder, createPlaybook, navigate]);

  const handleEdit = useCallback(
    (id: string) => {
      navigate(`/playbooks/builder/${id}`);
      setMenuOpenId(null);
    },
    [navigate],
  );

  const handleExecute = useCallback(
    (id: string) => {
      navigate(`/playbooks/${id}/execute`);
    },
    [navigate],
  );

  const handleToggleActive = useCallback(
    async (playbook: Playbook) => {
      try {
        await apiUpdatePlaybook(playbook.id, { is_active: !playbook.is_active });
        fetchPlaybooks();
      } catch {
        // Handle silently, will refresh on next fetch
      }
    },
    [fetchPlaybooks],
  );

  const handleDelete = useCallback(
    async (id: string) => {
      if (!confirm("Are you sure you want to delete this playbook?")) return;
      try {
        await apiDeletePlaybook(id);
        fetchPlaybooks();
      } catch {
        // Handle silently
      }
      setMenuOpenId(null);
    },
    [fetchPlaybooks],
  );

  return (
    <div className="flex flex-col h-full" data-testid="playbook-list">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border/50">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-indigo-600/20 border border-indigo-500/30">
            <Workflow className="w-4 h-4 text-indigo-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">Playbooks</h1>
            <p className="text-sm text-muted-foreground">
              Automated response workflows
            </p>
          </div>
        </div>
        <button
          onClick={handleNewPlaybook}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-white text-sm font-medium rounded-lg hover:bg-primary transition-colors"
          data-testid="playbook-list-new-button"
        >
          <Plus className="w-4 h-4" aria-hidden="true" />
          New Playbook
        </button>
      </div>

      {/* Search bar */}
      <div className="px-6 py-3 border-b border-border/30">
        <div className="relative max-w-md">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
            aria-hidden="true"
          />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search playbooks..."
            aria-label="Search playbooks"
            data-testid="playbook-list-search-input"
            className="w-full pl-9 pr-4 py-2 text-sm bg-accent border border-border rounded-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-colors"
          />
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
        {isLoading && playbooks.length === 0 && (
          <div
            className="flex items-center justify-center h-32"
            data-testid="playbook-list-loading"
          >
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        )}

        {error && (
          <div
            className="mb-4 px-4 py-3 bg-destructive/10 border border-red-500/20 rounded-lg text-sm text-destructive"
            role="alert"
            data-testid="playbook-list-error"
          >
            {error}
          </div>
        )}

        {!isLoading && filteredPlaybooks.length === 0 && (
          <div
            className="flex flex-col items-center justify-center py-16 text-center"
            data-testid="playbook-list-empty"
          >
            <Workflow className="w-12 h-12 text-muted-foreground/60 mb-3" aria-hidden="true" />
            <h3 className="text-sm font-medium text-foreground">
              {searchQuery ? "No matching playbooks" : "No playbooks yet"}
            </h3>
            <p className="text-xs text-muted-foreground mt-1 max-w-sm">
              {searchQuery
                ? "Try adjusting your search."
                : "Create your first automated response playbook using the visual builder."}
            </p>
            {!searchQuery && (
              <button
                onClick={handleNewPlaybook}
                className="mt-4 flex items-center gap-2 px-4 py-2 text-sm font-medium text-primary bg-primary/10 border border-primary/20 rounded-lg hover:bg-primary/20 transition-colors"
                data-testid="playbook-list-empty-new-button"
              >
                <Plus className="w-4 h-4" aria-hidden="true" />
                Create Playbook
              </button>
            )}
          </div>
        )}

        {/* Only mount the grid when we actually have rows to render —
            otherwise the empty-state and the (zero-row) grid are
            simultaneously visible and any locator that ORs the two
            (e.g. ``empty.or(grid)``) hits a strict-mode violation. */}
        {filteredPlaybooks.length > 0 && (
        <div
          className="grid gap-4 sm:grid-cols-1 md:grid-cols-2 lg:grid-cols-3"
          data-testid="playbook-list-grid"
        >
          {filteredPlaybooks.map((playbook) => {
            const badge = TRIGGER_BADGES[playbook.trigger?.type ?? TriggerType.MANUAL] ?? TRIGGER_BADGES[TriggerType.MANUAL]!;
            return (
              <div
                key={playbook.id}
                className="relative bg-accent/50 border border-border/50 rounded-xl p-4 hover:border-border/50 transition-all duration-150 group"
                data-testid={`playbook-list-item-${playbook.id}`}
              >
                {/* Top row: name + menu */}
                <div className="flex items-start justify-between mb-2">
                  <div className="min-w-0 flex-1">
                    <h3 className="text-sm font-semibold text-foreground truncate">
                      {playbook.name}
                    </h3>
                    <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                      {playbook.description || "No description"}
                    </p>
                  </div>
                  <div className="relative ml-2">
                    <button
                      onClick={() =>
                        setMenuOpenId(menuOpenId === playbook.id ? null : playbook.id)
                      }
                      className="p-1 rounded text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                      aria-label="Open playbook menu"
                      aria-expanded={menuOpenId === playbook.id}
                      data-testid={`playbook-list-item-${playbook.id}-menu-button`}
                    >
                      <MoreVertical className="w-4 h-4" aria-hidden="true" />
                    </button>
                    {menuOpenId === playbook.id && (
                      <div
                        className="absolute right-0 top-full mt-1 w-36 bg-accent border border-border rounded-lg shadow-xl z-10 py-1"
                        role="menu"
                        data-testid={`playbook-list-item-${playbook.id}-menu`}
                      >
                        <button
                          onClick={() => handleEdit(playbook.id)}
                          className="flex items-center gap-2 w-full px-3 py-1.5 text-xs text-foreground hover:bg-muted transition-colors"
                          role="menuitem"
                          data-testid={`playbook-list-item-${playbook.id}-edit-button`}
                        >
                          <Pencil className="w-3 h-3" aria-hidden="true" />
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(playbook.id)}
                          className="flex items-center gap-2 w-full px-3 py-1.5 text-xs text-destructive hover:bg-muted transition-colors"
                          role="menuitem"
                          data-testid={`playbook-list-item-${playbook.id}-delete-button`}
                        >
                          <Trash2 className="w-3 h-3" aria-hidden="true" />
                          Delete
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Badges */}
                <div className="flex items-center gap-2 mb-3">
                  <span
                    className={clsx(
                      "inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-semibold rounded-full border",
                      badge.className,
                    )}
                  >
                    <Zap className="w-2.5 h-2.5" aria-hidden="true" />
                    {badge.label}
                  </span>
                  <span className="text-[10px] text-muted-foreground font-medium">
                    v{playbook.version ?? "1.0"}
                  </span>
                </div>

                {/* Stats */}
                <div className="flex items-center gap-4 mb-3 text-xs text-muted-foreground">
                  <div className="flex items-center gap-1">
                    <BarChart3 className="w-3 h-3" aria-hidden="true" />
                    <span>{playbook.execution_count ?? 0} runs</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Clock className="w-3 h-3" aria-hidden="true" />
                    <span>{formatRelativeTime(playbook.last_executed_at ?? null)}</span>
                  </div>
                </div>

                {/* Actions row */}
                <div className="flex items-center gap-2 pt-2 border-t border-border/30">
                  <button
                    onClick={() => handleExecute(playbook.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-green-400 bg-green-500/10 border border-green-500/20 rounded-md hover:bg-green-500/20 transition-colors flex-1 justify-center"
                    data-testid={`playbook-list-item-${playbook.id}-execute-button`}
                  >
                    <Play className="w-3 h-3" aria-hidden="true" />
                    Execute
                  </button>
                  <button
                    onClick={() => handleToggleActive(playbook)}
                    className={clsx(
                      "px-3 py-1.5 text-xs font-medium rounded-md border transition-colors",
                      playbook.is_active
                        ? "text-green-400 bg-green-500/10 border-green-500/20 hover:bg-green-500/20"
                        : "text-muted-foreground bg-accent border-border hover:bg-muted",
                    )}
                    aria-pressed={playbook.is_active}
                    data-testid={`playbook-list-item-${playbook.id}-active-toggle`}
                  >
                    {playbook.is_active ? "Active" : "Inactive"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
        )}
      </div>
    </div>
  );
}
