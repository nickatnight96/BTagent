/**
 * Org-custom hunt packs panel (#112 slice 2) — the upload half of the
 * HuntPacks screen. An uploaded bundle (pack.yaml + rules/*.yml) is validated
 * server-side by the SAME engine loader the builtin packs go through; a pack
 * that appears in this list is a pack the scheduled sweep runs. Uploaded
 * packs are enabled by existence — delete (two-step, matching the safelist /
 * TAXII conventions) removes them from the sweep.
 *
 * The file input accepts the pack's files directly: pick pack.yaml together
 * with its rule .yml files and the panel reads them client-side into the
 * upload body. Validation failures surface the server's 422 verbatim — the
 * loader's message is the fix instruction.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Loader2, PackagePlus, Trash2 } from "lucide-react";

import {
  deleteCustomPack,
  listCustomPacks,
  uploadCustomPack,
  type CustomPack,
} from "@/api/hunt";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ds/button";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";

function errMessage(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const detail = (e.body as { detail?: unknown } | null)?.detail;
    if (typeof detail === "string" && detail) return detail;
    if (detail !== undefined) return JSON.stringify(detail);
  }
  return fallback;
}

export function CustomPacksPanel() {
  const role = useAuthStore((s) => s.user?.role);
  const canManage =
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.ADMIN;

  const [packs, setPacks] = useState<CustomPack[] | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const load = useCallback(async () => {
    try {
      const resp = await listCustomPacks();
      setPacks(resp.items);
    } catch {
      // Self-effacing on failure, matching the panel convention.
      setPacks(null);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (packs === null) return null;

  const handleFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setUploading(true);
    setError(null);
    try {
      let manifest: string | null = null;
      const ruleFiles: Record<string, string> = {};
      for (const file of Array.from(files)) {
        const text = await file.text();
        if (file.name === "pack.yaml" || file.name === "pack.yml") {
          manifest = text;
        } else if (file.name.endsWith(".yml") || file.name.endsWith(".yaml")) {
          ruleFiles[file.name] = text;
        }
      }
      if (manifest === null) {
        setError("Select the pack.yaml manifest together with its rule .yml files.");
        return;
      }
      await uploadCustomPack({ manifest_yaml: manifest, rule_files: ruleFiles });
      await load();
    } catch (e) {
      // The contentful refusal is the loader's 422 — show it as-is.
      setError(errMessage(e, "Failed to upload pack."));
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handleDelete = async (rowId: string) => {
    // Two-step: the first click arms, the second deletes.
    if (confirmDeleteId !== rowId) {
      setConfirmDeleteId(rowId);
      return;
    }
    setBusyId(rowId);
    setError(null);
    try {
      await deleteCustomPack(rowId);
      setConfirmDeleteId(null);
      await load();
    } catch (e) {
      setError(errMessage(e, "Failed to delete pack."));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <section
      className="rounded-lg border border-border bg-card/50 p-4"
      data-testid="custom-packs-panel"
    >
      <div className="mb-2 flex items-center gap-2">
        <PackagePlus className="h-4 w-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Custom packs</h2>
        <span className="text-xs text-muted-foreground">
          org-authored Sigma bundles — validated by the same loader as the builtin packs,
          run on every sweep
        </span>
      </div>

      {packs.length === 0 ? (
        <p className="text-xs text-muted-foreground" data-testid="custom-packs-empty">
          No custom packs uploaded. Upload a pack.yaml with its rule files to add
          org-specific hunts to the scheduled sweep.
        </p>
      ) : (
        <ul className="space-y-2" data-testid="custom-packs-list">
          {packs.map((pack) => (
            <li
              key={pack.id}
              className="flex flex-wrap items-center gap-2 rounded-md border border-slate-800 bg-slate-800/40 px-3 py-2 text-sm"
              data-testid={`custom-pack-${pack.id}`}
            >
              <span className="font-medium text-slate-200">{pack.name}</span>
              <span className="font-mono text-xs text-slate-400">v{pack.version}</span>
              <span className="text-xs text-slate-500" data-testid="custom-pack-rules">
                {pack.rule_count} rule{pack.rule_count === 1 ? "" : "s"}
              </span>
              {pack.description && (
                <span className="truncate text-xs text-slate-500">{pack.description}</span>
              )}
              {canManage && (
                <span className="ml-auto">
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={busyId === pack.id}
                    onClick={() => void handleDelete(pack.id)}
                    data-testid={`custom-pack-delete-${pack.id}`}
                  >
                    <Trash2 className="mr-1 h-3.5 w-3.5" />
                    {confirmDeleteId === pack.id ? "Confirm delete" : "Delete"}
                  </Button>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}

      {canManage && (
        <div className="mt-3 flex flex-wrap items-center gap-2" data-testid="custom-pack-form">
          <input
            ref={fileInputRef}
            type="file"
            multiple
            accept=".yml,.yaml"
            aria-label="Pack files"
            data-testid="custom-pack-files"
            className="text-xs text-slate-400 file:mr-2 file:rounded-md file:border file:border-border file:bg-background file:px-2 file:py-1 file:text-xs"
            onChange={(e) => void handleFiles(e.target.files)}
            disabled={uploading}
          />
          {uploading && <Loader2 className="h-4 w-4 animate-spin text-slate-400" />}
          <span className="text-xs text-muted-foreground">
            Select pack.yaml together with its rule .yml files.
          </span>
        </div>
      )}

      {error && (
        <p
          className="mt-2 text-xs text-severity-medium"
          role="alert"
          data-testid="custom-packs-error"
        >
          {error}
        </p>
      )}
    </section>
  );
}
