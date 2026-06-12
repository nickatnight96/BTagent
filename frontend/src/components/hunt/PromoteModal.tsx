import { useEffect, useRef, useState } from "react";
import { ArrowUpRight } from "lucide-react";
import type { HuntFinding, HuntFindingCluster } from "@/types/hunt";
import { useHuntStore } from "@/stores/huntStore";
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

export interface PromoteFindingTarget {
  kind: "finding";
  finding: HuntFinding;
}

export interface PromoteClusterTarget {
  kind: "cluster";
  cluster: HuntFindingCluster;
}

export type PromoteModalTarget = PromoteFindingTarget | PromoteClusterTarget;

interface PromoteModalProps {
  target: PromoteModalTarget | null;
  onClose: () => void;
}

export function PromoteModal({ target, onClose }: PromoteModalProps) {
  const promote = useHuntStore((s) => s.promote);
  const promoteClusterAction = useHuntStore((s) => s.promoteCluster);
  const isMutating = useHuntStore((s) => s.isMutating);

  const [title, setTitle] = useState("");
  const [createdInvId, setCreatedInvId] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  const titleRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (target) {
      setTitle("");
      setCreatedInvId(null);
      setLocalError(null);
      setTimeout(() => titleRef.current?.focus(), 50);
    }
  }, [target]);

  if (!target) return null;

  const sourceName = target.kind === "finding" ? target.finding.title : target.cluster.title;
  const isCluster = target.kind === "cluster";

  const handleSubmit = async () => {
    setLocalError(null);
    try {
      let invId: string;
      if (target.kind === "finding") {
        invId = await promote([target.finding.id], title.trim() || undefined);
      } else {
        invId = await promoteClusterAction(target.cluster.id, {
          title: title.trim() || undefined,
        });
      }
      setCreatedInvId(invId);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Promotion failed";
      setLocalError(msg);
    }
  };

  return (
    <Dialog open={!!target} onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent data-testid="hunt-promote-modal">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ArrowUpRight className="w-4 h-4 text-blue-400" aria-hidden="true" />
            {isCluster ? "Promote cluster" : "Promote finding"} to investigation
          </DialogTitle>
          <DialogDescription className="truncate text-xs text-muted-foreground">
            {sourceName}
          </DialogDescription>
        </DialogHeader>

        {createdInvId ? (
          <div className="py-4 space-y-4">
            <div
              className="rounded-md border border-primary/30 bg-primary/10 p-3 text-sm"
              data-testid="hunt-promote-success"
            >
              Investigation created successfully.
            </div>
            <Button
              asChild
              className="w-full"
              data-testid="hunt-promote-investigation-link"
            >
              <a href={`/investigations/${createdInvId}`}>
                View investigation
              </a>
            </Button>
          </div>
        ) : (
          <>
            <div className="space-y-4 py-2">
              <div className="space-y-1.5">
                <Label htmlFor="promote-title">
                  Investigation title{" "}
                  <span className="text-muted-foreground text-xs">(optional)</span>
                </Label>
                <Input
                  id="promote-title"
                  ref={titleRef}
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder={sourceName}
                  data-testid="hunt-promote-title"
                />
              </div>

              {localError && (
                <div
                  className="rounded-md border border-destructive/30 bg-destructive/10 p-2.5 text-sm text-destructive"
                  role="alert"
                  data-testid="hunt-promote-error"
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
                disabled={isMutating}
                data-testid="hunt-promote-submit"
              >
                {isMutating ? "Promoting…" : "Promote"}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
