import { useEffect, useRef, useState } from "react";
import { X, ShieldOff } from "lucide-react";
import type { HuntFinding, HuntFindingCluster, SuppressionMatch } from "@/types/hunt";
import { useHuntStore } from "@/stores/huntStore";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ds/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ds/dialog";
import { Input } from "@/components/ds/input";
import { Label } from "@/components/ds/label";
import { Textarea } from "@/components/ds/textarea";

export interface SuppressTarget {
  kind: "finding";
  finding: HuntFinding;
}

export interface SuppressClusterTarget {
  kind: "cluster";
  cluster: HuntFindingCluster;
}

export type SuppressModalTarget = SuppressTarget | SuppressClusterTarget;

interface SuppressModalProps {
  target: SuppressModalTarget | null;
  onClose: () => void;
}

/** Build the default suppression criteria from a finding's own shape. */
function defaultMatchFromFinding(finding: HuntFinding): SuppressionMatch {
  return {
    source: finding.source,
    domain: null,
    technique_ids: [...finding.technique_ids],
    entity_values: [],
    observable_values: [],
  };
}

/** Build the default suppression criteria from a cluster's pattern. */
function defaultMatchFromCluster(cluster: HuntFindingCluster): SuppressionMatch {
  return {
    source: null,
    domain: cluster.domain,
    technique_ids: [...cluster.technique_ids],
    entity_values: [],
    observable_values: [],
  };
}

export function SuppressModal({ target, onClose }: SuppressModalProps) {
  const suppress = useHuntStore((s) => s.suppress);
  const suppressClusterAction = useHuntStore((s) => s.suppressCluster);
  const isMutating = useHuntStore((s) => s.isMutating);

  const [name, setName] = useState("");
  const [reason, setReason] = useState("");
  const [reconfirmDays, setReconfirmDays] = useState(90);
  const [localError, setLocalError] = useState<string | null>(null);

  const nameRef = useRef<HTMLInputElement>(null);

  // Reset fields when the modal opens for a new target
  useEffect(() => {
    if (target) {
      setName("");
      setReason("");
      setReconfirmDays(90);
      setLocalError(null);
      // Focus name field after render
      setTimeout(() => nameRef.current?.focus(), 50);
    }
  }, [target]);

  if (!target) return null;

  const match =
    target.kind === "finding"
      ? defaultMatchFromFinding(target.finding)
      : defaultMatchFromCluster(target.cluster);

  const title = target.kind === "finding" ? target.finding.title : target.cluster.title;
  const isCluster = target.kind === "cluster";

  const handleSubmit = async () => {
    setLocalError(null);
    if (!name.trim()) {
      setLocalError("Rule name is required.");
      nameRef.current?.focus();
      return;
    }
    if (!reason.trim()) {
      setLocalError("Rationale is required — this forms the audit trail.");
      return;
    }
    const body = {
      name: name.trim(),
      reason: reason.trim(),
      match: isCluster ? undefined : match, // cluster derives from its own pattern
      reconfirm_in_hours: reconfirmDays * 24,
    };
    try {
      if (target.kind === "finding") {
        await suppress(target.finding.id, { ...body, match });
      } else {
        await suppressClusterAction(target.cluster.id, body);
      }
      onClose();
    } catch (err) {
      // Prefer the backend's body.detail (carries the over-broad message on 409).
      let msg = "Suppression failed";
      if (err instanceof ApiError) {
        const apiBody = err.body as { detail?: string } | null;
        msg = apiBody?.detail ?? err.message;
      } else if (err instanceof Error) {
        msg = err.message;
      }
      setLocalError(msg);
    }
  };

  const canSubmit = name.trim().length > 0 && reason.trim().length > 0 && !isMutating;

  const displayMatch = isCluster ? defaultMatchFromCluster(target.cluster) : match;

  return (
    <Dialog open={!!target} onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent data-testid="hunt-suppress-modal">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldOff className="w-4 h-4 text-amber-400" aria-hidden="true" />
            {isCluster ? "Suppress cluster" : "Suppress finding"}
          </DialogTitle>
          <DialogDescription className="truncate text-xs text-muted-foreground">
            {title}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="suppress-name">Rule name</Label>
            <Input
              id="suppress-name"
              ref={nameRef}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Approved admin tooling on jump hosts"
              data-testid="hunt-suppress-name"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="suppress-reason">
              Reason <span className="text-destructive">*</span>
            </Label>
            <Textarea
              id="suppress-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              placeholder="Why is this expected / benign? This text is the audit trail."
              data-testid="hunt-suppress-reason"
            />
          </div>

          <div className="space-y-1.5">
            <span className="block text-xs font-medium text-muted-foreground">
              Match scope (derived from {isCluster ? "cluster" : "finding"})
            </span>
            <div
              className="flex flex-wrap gap-1.5 rounded-md border border-border bg-muted/30 p-2"
              data-testid="hunt-suppress-match-scope"
            >
              {displayMatch.source && (
                <span className="px-2 py-0.5 rounded-full text-xs bg-secondary text-secondary-foreground border border-border">
                  source: {displayMatch.source}
                </span>
              )}
              {displayMatch.domain && (
                <span className="px-2 py-0.5 rounded-full text-xs bg-secondary text-secondary-foreground border border-border">
                  domain: {displayMatch.domain}
                </span>
              )}
              {displayMatch.technique_ids.map((t) => (
                <span
                  key={t}
                  className="px-2 py-0.5 rounded-full text-xs bg-blue-500/10 text-blue-300 border border-blue-500/20"
                >
                  {t}
                </span>
              ))}
              {!displayMatch.source &&
                !displayMatch.domain &&
                displayMatch.technique_ids.length === 0 && (
                  <span className="text-xs text-muted-foreground italic">
                    No match criteria — will match broadly.
                  </span>
                )}
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="suppress-reconfirm">Re-confirm after (days)</Label>
            <Input
              id="suppress-reconfirm"
              type="number"
              min={1}
              max={365}
              value={reconfirmDays}
              onChange={(e) => setReconfirmDays(Number(e.target.value))}
              className="w-28"
              data-testid="hunt-suppress-reconfirm"
            />
          </div>

          {localError && (
            <div
              className="rounded-md border border-destructive/30 bg-destructive/10 p-2.5 text-sm text-destructive"
              role="alert"
              data-testid="hunt-suppress-error"
            >
              {localError}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={isMutating}>
            Cancel
          </Button>
          <Button
            onClick={() => { void handleSubmit(); }}
            disabled={!canSubmit}
            className="bg-amber-600 text-white hover:bg-amber-700"
            data-testid="hunt-suppress-submit"
          >
            {isMutating ? (
              <>
                <X className="w-4 h-4 mr-2 animate-spin" />
                Suppressing…
              </>
            ) : (
              "Suppress"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
